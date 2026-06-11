//! Wait for a child PID to exit and return its exit code (Frida-spawned processes are not
//! direct children of Guardian, so `std::process::Child::wait` is unavailable).

use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

pub struct ChildExitWaiter {
    exit_rx: Receiver<Result<i32>>,
    thread: Option<JoinHandle<()>>,
}

impl ChildExitWaiter {
    pub fn start(pid: u32) -> Result<Self> {
        let (exit_tx, exit_rx) = mpsc::channel();
        let thread = thread::Builder::new()
            .name(format!("child-exit-{pid}"))
            .spawn(move || {
                let result = wait_for_exit(pid);
                let _ = exit_tx.send(result);
            })
            .context("failed to spawn child exit waiter thread")?;
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

fn wait_for_exit(pid: u32) -> Result<i32> {
    #[cfg(target_os = "linux")]
    {
        return wait_linux(pid);
    }
    #[cfg(target_os = "macos")]
    {
        return wait_macos(pid);
    }
    #[cfg(windows)]
    {
        return wait_windows(pid);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = pid;
        anyhow::bail!("child exit waiting is not implemented on this platform");
    }
}

#[cfg(target_os = "linux")]
fn wait_linux(pid: u32) -> Result<i32> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if pidfd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("pidfd_open failed for pid {pid}"));
    }
    let pidfd = pidfd as i32;

    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd as libc::id_t,
            &mut info as *mut libc::siginfo_t,
            libc::WEXITED,
        )
    };
    let wait_err = if ret < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe {
        libc::close(pidfd);
    }
    if let Some(err) = wait_err {
        return Err(err).with_context(|| format!("waitid failed for pid {pid}"));
    }
    Ok(exit_code_from_siginfo(&info))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn exit_code_from_siginfo(info: &libc::siginfo_t) -> i32 {
    let status = unsafe { info.si_status() };
    if info.si_code == libc::CLD_EXITED as i32 {
        status
    } else {
        128 + (status & 0x7f)
    }
}

#[cfg(target_os = "macos")]
fn wait_macos(pid: u32) -> Result<i32> {
    unsafe {
        let kq = libc::kqueue();
        if kq < 0 {
            return Err(std::io::Error::last_os_error()).context("kqueue failed");
        }

        let mut kev: libc::kevent = std::mem::zeroed();
        libc::EV_SET(
            &mut kev,
            pid as libc::uintptr_t,
            libc::EVFILT_PROC,
            libc::EV_ADD,
            libc::NOTE_EXIT,
            0,
        );
        if libc::kevent(kq, &kev, 1, std::ptr::null_mut(), 0, std::ptr::null()) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(kq);
            return Err(err).with_context(|| format!("kevent register failed for pid {pid}"));
        }

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

        let status = out_kev.data as i32;
        Ok((status >> 8) & 0xff)
    }
}

#[cfg(windows)]
fn wait_windows(pid: u32) -> Result<i32> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, WaitForSingleObject, INFINITE,
        PROCESS_QUERY_LIMITED_INFORMATION, SYNCHRONIZE,
    };

    const STILL_ACTIVE: u32 = 259;

    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("OpenProcess failed for pid {pid}"));
    }

    let wait = unsafe { WaitForSingleObject(handle, INFINITE) };
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

    use super::ChildExitWaiter;

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
}
