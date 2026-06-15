//! Wait for a Frida-spawned PID to exit and return its exit code. These processes are OS
//! children of Guardian but are not wrapped in `std::process::Child`, so the normal Rust wait
//! API is unavailable.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

pub struct ChildExitWaiter {
    exit_rx: Receiver<Result<i32>>,
    thread: Option<JoinHandle<()>>,
}

impl ChildExitWaiter {
    /// Open/register the OS exit wait synchronously, spawn a blocking waiter, and return only
    /// after the waiter thread is about to enter its blocking wait syscall.
    pub fn start(pid: u32) -> Result<Self> {
        let (exit_tx, exit_rx) = mpsc::channel();
        let (armed_tx, armed_rx) = mpsc::sync_channel(0);

        #[cfg(target_os = "linux")]
        let prepared = PreparedWait::Linux(prepare_linux_wait(pid)?);
        #[cfg(target_os = "macos")]
        let prepared = PreparedWait::Mac(prepare_macos_wait(pid)?);
        #[cfg(windows)]
        let prepared = PreparedWait::Windows(prepare_windows_wait(pid)?);

        let thread = thread::Builder::new()
            .name(format!("child-exit-{pid}"))
            .spawn(move || {
                let result = finish_prepared_wait(pid, prepared, armed_tx);
                let _ = exit_tx.send(result);
            })
            .context("failed to spawn child exit waiter thread")?;

        armed_rx
            .recv()
            .context("child exit waiter failed to arm blocking wait")?;

        Ok(Self {
            exit_rx,
            thread: Some(thread),
        })
    }

    pub fn try_recv_exit(&self, timeout: Duration) -> Result<Option<i32>> {
        match self.exit_rx.recv_timeout(timeout) {
            Ok(Ok(code)) => Ok(Some(code)),
            Ok(Err(err)) => Err(err),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                anyhow::bail!("child exit waiter thread exited without sending status")
            }
        }
    }

    pub fn wait(mut self) -> Result<i32> {
        let code = self
            .exit_rx
            .recv()
            .context("child exit waiter thread exited without sending status")??;
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
        Ok(code)
    }
}

impl Drop for ChildExitWaiter {
    fn drop(&mut self) {
        // Detach without join: on SIGINT the child may outlive guardian briefly; joining
        // would block shutdown until the process tree exits.
        let _ = self.thread.take();
    }
}

enum PreparedWait {
    #[cfg(target_os = "linux")]
    Linux(LinuxWait),
    #[cfg(target_os = "macos")]
    Mac(MacosWait),
    #[cfg(windows)]
    Windows(WindowsWait),
}

fn finish_prepared_wait(pid: u32, prepared: PreparedWait, armed_tx: SyncSender<()>) -> Result<i32> {
    match prepared {
        #[cfg(target_os = "linux")]
        PreparedWait::Linux(wait) => finish_linux_wait(pid, wait, armed_tx),
        #[cfg(target_os = "macos")]
        PreparedWait::Mac(wait) => finish_macos_wait(pid, wait, armed_tx),
        #[cfg(windows)]
        PreparedWait::Windows(wait) => finish_windows_wait(pid, wait, armed_tx),
    }
}

fn signal_armed(armed_tx: &SyncSender<()>) -> Result<()> {
    armed_tx
        .send(())
        .context("failed to signal child exit waiter armed")
}

/// Best-effort reap when the process has exited but may still be a zombie.
pub(crate) fn try_reap_child_exit(pid: u32) -> Option<i32> {
    #[cfg(unix)]
    {
        let mut status: i32 = 0;
        let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
        if ret == pid as libc::pid_t {
            return Some(exit_code_from_wait_status(status));
        }
        return None;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        };

        const STILL_ACTIVE: u32 = 259;

        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            return None;
        }
        let mut code: u32 = 0;
        let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
        unsafe { CloseHandle(handle) };
        if ok == 0 || code == STILL_ACTIVE {
            return None;
        }
        Some(code as i32)
    }
}

pub(crate) fn is_reap_race_err(err: &anyhow::Error) -> bool {
    #[cfg(unix)]
    {
        return err.chain().any(|cause| {
            matches!(
                cause
                    .downcast_ref::<std::io::Error>()
                    .and_then(|io| io.raw_os_error()),
                Some(libc::ECHILD) | Some(libc::ESRCH)
            )
        });
    }
    #[cfg(not(unix))]
    {
        let _ = err;
        false
    }
}

#[cfg(unix)]
fn exit_code_from_wait_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        0
    }
}

#[cfg(target_os = "linux")]
struct LinuxWait;

#[cfg(target_os = "linux")]
fn prepare_linux_wait(pid: u32) -> Result<LinuxWait> {
    let ret = unsafe { libc::kill(pid as i32, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("process {pid} is not waitable"));
    }
    Ok(LinuxWait)
}

#[cfg(target_os = "linux")]
fn finish_linux_wait(pid: u32, _wait: LinuxWait, armed_tx: SyncSender<()>) -> Result<i32> {
    signal_armed(&armed_tx)?;
    let mut status: i32 = 0;
    let ret = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("waitpid failed for pid {pid}"));
    }
    Ok(exit_code_from_wait_status(status))
}

#[cfg(target_os = "macos")]
struct MacosWait {
    kq: i32,
}

#[cfg(target_os = "macos")]
fn prepare_macos_wait(pid: u32) -> Result<MacosWait> {
    const NOTE_EXITSTATUS: libc::uint32_t = 0x0400_0000;

    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            return Err(std::io::Error::last_os_error()).context("kqueue failed");
        }

        let mut kev: libc::kevent = std::mem::zeroed();
        kev.ident = pid as libc::uintptr_t;
        kev.filter = libc::EVFILT_PROC;
        kev.flags = libc::EV_ADD;
        kev.fflags = libc::NOTE_EXIT | NOTE_EXITSTATUS;
        kev.data = 0;
        kev.udata = std::ptr::null_mut();
        if libc::kevent(kq, &kev, 1, std::ptr::null_mut(), 0, std::ptr::null()) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(kq);
            return Err(err).with_context(|| format!("kevent register failed for pid {pid}"));
        }

        Ok(MacosWait { kq })
    }
}

#[cfg(target_os = "macos")]
fn finish_macos_wait(pid: u32, wait: MacosWait, armed_tx: SyncSender<()>) -> Result<i32> {
    let MacosWait { kq } = wait;
    signal_armed(&armed_tx)?;

    unsafe {
        let mut out_kev: libc::kevent = std::mem::zeroed();
        if libc::kevent(
            kq,
            std::ptr::null_mut(),
            0,
            &mut out_kev,
            1,
            std::ptr::null(),
        ) < 0
        {
            let err = std::io::Error::last_os_error();
            libc::close(kq);
            return Err(err).with_context(|| format!("kevent wait failed for pid {pid}"));
        }
        libc::close(kq);

        Ok(exit_code_from_kqueue_status(out_kev.data as i32))
    }
}

#[cfg(target_os = "macos")]
fn exit_code_from_kqueue_status(status: i32) -> i32 {
    if (0..=0xff).contains(&status) {
        status
    } else {
        (status >> 8) & 0xff
    }
}

#[cfg(windows)]
struct WindowsWait {
    // HANDLE is not Send; store as usize for cross-thread handoff to the waiter thread.
    handle: usize,
}

#[cfg(windows)]
fn prepare_windows_wait(pid: u32) -> Result<WindowsWait> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("OpenProcess failed for pid {pid}"));
    }
    Ok(WindowsWait {
        handle: handle as usize,
    })
}

#[cfg(windows)]
fn finish_windows_wait(pid: u32, wait: WindowsWait, armed_tx: SyncSender<()>) -> Result<i32> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

    const STILL_ACTIVE: u32 = 259;

    let handle = wait.handle as HANDLE;
    signal_armed(&armed_tx)?;

    let wait = unsafe { WaitForSingleObject(handle, u32::MAX) };
    if wait != WAIT_OBJECT_0 {
        unsafe { CloseHandle(handle) };
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("WaitForSingleObject failed for pid {pid}"));
    }

    let mut code: u32 = 0;
    let ok = unsafe { GetExitCodeProcess(handle, &mut code) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("GetExitCodeProcess failed for pid {pid}"));
    }
    if code == STILL_ACTIVE {
        anyhow::bail!("pid {pid} still active after wait");
    }
    Ok(code as i32)
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    use super::ChildExitWaiter;

    #[test]
    fn waiter_collects_exit_for_immediate_child() {
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "exit 4"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        #[cfg(windows)]
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit 4"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        let waiter = ChildExitWaiter::start(pid).expect("start waiter");
        assert_eq!(waiter.wait().expect("waiter exit code"), 4);
        drop(child);
    }

    #[test]
    fn waiter_returns_child_exit_code() {
        #[cfg(windows)]
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit", "3"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "exit 3"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        let waiter = ChildExitWaiter::start(pid).expect("start waiter");
        let got = waiter.wait().expect("waiter exit code");
        assert_eq!(got, 3);
        drop(child);
    }

    #[test]
    fn try_reap_missing_pid_returns_none() {
        assert!(super::try_reap_child_exit(4_000_000).is_none());
    }

    #[test]
    fn try_reap_returns_none_for_running_child() {
        #[cfg(windows)]
        let mut child = Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        assert!(super::try_reap_child_exit(pid).is_none());
        child.kill().expect("kill child");
        let _ = child.wait();
    }

    #[test]
    fn try_reap_reads_exited_child_code() {
        #[cfg(windows)]
        let mut child = Command::new("cmd.exe")
            .args(["/C", "exit", "5"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "exit 5"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut code = None;
        while std::time::Instant::now() < deadline {
            if let Some(exit) = super::try_reap_child_exit(pid) {
                code = Some(exit);
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.wait();
        assert_eq!(code, Some(5), "try_reap should observe exit code 5");
    }

    #[test]
    fn try_recv_exit_times_out_for_running_child() {
        #[cfg(windows)]
        let mut child = Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");
        #[cfg(not(windows))]
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child");

        let pid = child.id();
        let waiter = ChildExitWaiter::start(pid).expect("start waiter");
        assert!(waiter
            .try_recv_exit(Duration::from_millis(50))
            .expect("recv")
            .is_none());
        child.kill().expect("kill child");
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn is_reap_race_err_recognizes_echild() {
        let err = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::ECHILD));
        assert!(super::is_reap_race_err(&err));
        let err = anyhow::Error::from(std::io::Error::from_raw_os_error(libc::ESRCH));
        assert!(super::is_reap_race_err(&err));
        let err = anyhow::Error::msg("other");
        assert!(!super::is_reap_race_err(&err));
    }
}
