use std::ffi::CString;

use anyhow::{bail, Result};
use frida::Session;
use frida_sys::{
    frida_child_get_pid, frida_session_enable_child_gating_sync,
    _frida_g_signal_connect_data, _frida_g_signal_handler_disconnect, gpointer, GCallback,
    FridaSessionDetachReason, FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED,
};

unsafe fn session_ptr(session: &Session) -> *mut frida_sys::_FridaSession {
    let ptr = session as *const Session as *const *mut frida_sys::_FridaSession;
    *ptr
}

unsafe fn device_ptr(device: &frida::Device) -> *mut frida_sys::_FridaDevice {
    let ptr = device as *const frida::Device as *const *mut frida_sys::_FridaDevice;
    *ptr
}

pub fn enable_child_gating(session: &Session) -> Result<()> {
    let mut error: *mut frida_sys::GError = std::ptr::null_mut();
    unsafe {
        frida_session_enable_child_gating_sync(session_ptr(session), std::ptr::null_mut(), &mut error);
    }
    if !error.is_null() {
        let msg = unsafe { std::ffi::CStr::from_ptr((*error).message) };
        bail!("enable_child_gating failed: {}", msg.to_string_lossy());
    }
    Ok(())
}

struct DeviceCallbacks {
    on_added: Box<dyn Fn(u32) + Send + Sync>,
    on_removed: Box<dyn Fn(u32) + Send + Sync>,
}

unsafe extern "C" fn on_child_added(
    _device: gpointer,
    child: *mut frida_sys::_FridaChild,
    user_data: gpointer,
) {
    if child.is_null() || user_data.is_null() {
        return;
    }
    let pid = frida_child_get_pid(child);
    let cb = &*(user_data as *const DeviceCallbacks);
    (cb.on_added)(pid);
}

unsafe extern "C" fn on_child_removed(
    _device: gpointer,
    child: *mut frida_sys::_FridaChild,
    user_data: gpointer,
) {
    if child.is_null() || user_data.is_null() {
        return;
    }
    let pid = frida_child_get_pid(child);
    let cb = &*(user_data as *const DeviceCallbacks);
    (cb.on_removed)(pid);
}

unsafe extern "C" fn destroy_device_callbacks(
    data: gpointer,
    _closure: *mut frida_sys::GClosure,
) {
    if !data.is_null() {
        let _ = Box::from_raw(data as *mut DeviceCallbacks);
    }
}

pub struct DeviceSignalHandle {
    device: usize,
    added_id: u64,
    removed_id: u64,
}

impl Drop for DeviceSignalHandle {
    fn drop(&mut self) {
        unsafe {
            let device = self.device as gpointer;
            _frida_g_signal_handler_disconnect(device, self.added_id);
            _frida_g_signal_handler_disconnect(device, self.removed_id);
        }
    }
}

pub fn connect_device_child_signals<A, R>(
    device: &frida::Device,
    on_added: A,
    on_removed: R,
) -> Result<DeviceSignalHandle>
where
    A: Fn(u32) + Send + Sync + 'static,
    R: Fn(u32) + Send + Sync + 'static,
{
    let callbacks = Box::new(DeviceCallbacks {
        on_added: Box::new(on_added),
        on_removed: Box::new(on_removed),
    });
    let user_data = Box::into_raw(callbacks) as gpointer;
    let device_gp = unsafe { device_ptr(device) as gpointer };

    let signal_added = CString::new("child-added").unwrap();
    let signal_removed = CString::new("child-removed").unwrap();

    let added_id = unsafe {
        _frida_g_signal_connect_data(
            device_gp,
            signal_added.as_ptr(),
            std::mem::transmute::<
                unsafe extern "C" fn(gpointer, *mut frida_sys::_FridaChild, gpointer),
                GCallback,
            >(on_child_added),
            user_data,
            Some(destroy_device_callbacks),
            0,
        )
    };

    let removed_id = unsafe {
        _frida_g_signal_connect_data(
            device_gp,
            signal_removed.as_ptr(),
            std::mem::transmute::<
                unsafe extern "C" fn(gpointer, *mut frida_sys::_FridaChild, gpointer),
                GCallback,
            >(on_child_removed),
            user_data,
            None,
            0,
        )
    };

    Ok(DeviceSignalHandle {
        device: device_gp as usize,
        added_id,
        removed_id,
    })
}

struct SessionDetachedCallback {
    on_detached: Box<dyn Fn(FridaSessionDetachReason) + Send + Sync>,
}

unsafe extern "C" fn on_session_detached(
    _session: *mut frida_sys::_FridaSession,
    reason: FridaSessionDetachReason,
    _crash: *mut frida_sys::_FridaCrash,
    user_data: gpointer,
) {
    if user_data.is_null() {
        return;
    }
    let cb = &*(user_data as *const SessionDetachedCallback);
    (cb.on_detached)(reason);
}

unsafe extern "C" fn destroy_session_callback(
    data: gpointer,
    _closure: *mut frida_sys::GClosure,
) {
    if !data.is_null() {
        let _ = Box::from_raw(data as *mut SessionDetachedCallback);
    }
}

pub struct SessionSignalHandle {
    session: usize,
    detached_id: u64,
}

impl Drop for SessionSignalHandle {
    fn drop(&mut self) {
        unsafe {
            let session = self.session as gpointer;
            _frida_g_signal_handler_disconnect(session, self.detached_id);
        }
    }
}

pub fn connect_session_detached<F>(session: &Session, on_detached: F) -> SessionSignalHandle
where
    F: Fn(FridaSessionDetachReason) + Send + Sync + 'static,
{
    let callbacks = Box::new(SessionDetachedCallback {
        on_detached: Box::new(on_detached),
    });
    let user_data = Box::into_raw(callbacks) as gpointer;
    let session_gp = unsafe { session_ptr(session) as gpointer };

    let signal = CString::new("detached").unwrap();
    let detached_id = unsafe {
        _frida_g_signal_connect_data(
            session_gp,
            signal.as_ptr(),
            std::mem::transmute::<
                unsafe extern "C" fn(
                    *mut frida_sys::_FridaSession,
                    FridaSessionDetachReason,
                    *mut frida_sys::_FridaCrash,
                    gpointer,
                ),
                GCallback,
            >(on_session_detached),
            user_data,
            Some(destroy_session_callback),
            0,
        )
    };

    SessionSignalHandle {
        session: session_gp as usize,
        detached_id,
    }
}

pub fn is_process_replaced(reason: FridaSessionDetachReason) -> bool {
    reason == FridaSessionDetachReason_FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED
}
