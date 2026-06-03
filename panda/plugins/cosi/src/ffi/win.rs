//! C-ABI surface for the Windows OSI walkers (panda-plus Win10/11 fork).
//!
//! Mirrors the Linux process-list FFI style: enumerations return an opaque
//! `Box<Vec<...>>`; callers iterate by index and free the list when done.
//! Query from a kernel-mode context (see win.rs KPTI note).

use crate::win::{self, WinHandle, WinMod, WinProc, WinProcParams};
use panda::prelude::*;
use std::{ffi::CString, os::raw::c_char};

fn to_cstr(s: &str) -> *mut c_char {
    CString::new(s)
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// ntoskrnl base address (KASLR-resolved), or 0 if undetermined.
#[no_mangle]
pub extern "C" fn cosi_win_kernel_base(cpu: &mut CPUState) -> target_ptr_t {
    win::kernel_base(cpu)
}

/// Pointer to the current _EPROCESS, or 0.
#[no_mangle]
pub extern "C" fn cosi_win_current_eprocess(cpu: &mut CPUState) -> target_ptr_t {
    win::current_eprocess(cpu).unwrap_or(0)
}

/// Current process as a WinProc (pid/ppid/name/eprocess), or null. Free with
/// `cosi_win_free_proc` (a Box of a single WinProc). Used by the osi bridge.
#[no_mangle]
pub extern "C" fn cosi_win_current_proc(cpu: &mut CPUState) -> Option<Box<WinProc>> {
    win::current_proc(cpu).map(Box::new)
}

#[no_mangle]
pub extern "C" fn cosi_win_free_proc(_p: Option<Box<WinProc>>) {}

/// Current thread id, or 0.
#[no_mangle]
pub extern "C" fn cosi_win_current_tid(cpu: &mut CPUState) -> u64 {
    win::current_tid(cpu).unwrap_or(0)
}

/// WinProc for a given _EPROCESS pointer. Free with `cosi_win_free_proc`.
#[no_mangle]
pub extern "C" fn cosi_win_proc_at(cpu: &mut CPUState, eprocess: target_ptr_t) -> Box<WinProc> {
    Box::new(win::proc_at(cpu, eprocess))
}

// ---- process list ----------------------------------------------------------

/// Get the active process list. Returns null if it could not be walked.
/// Free with `cosi_win_free_proc_list`.
#[no_mangle]
pub extern "C" fn cosi_win_get_proc_list(cpu: &mut CPUState) -> Option<Box<Vec<WinProc>>> {
    let l = win::proc_list(cpu);
    if l.is_empty() {
        None
    } else {
        Some(Box::new(l))
    }
}

#[no_mangle]
pub extern "C" fn cosi_win_proc_list_len(list: &Vec<WinProc>) -> usize {
    list.len()
}

#[no_mangle]
pub extern "C" fn cosi_win_proc_list_get(list: &Vec<WinProc>, index: usize) -> Option<&WinProc> {
    list.get(index)
}

#[no_mangle]
pub extern "C" fn cosi_win_free_proc_list(_list: Option<Box<Vec<WinProc>>>) {}

#[no_mangle]
pub extern "C" fn cosi_win_proc_pid(proc_: &WinProc) -> u64 {
    proc_.pid
}

#[no_mangle]
pub extern "C" fn cosi_win_proc_ppid(proc_: &WinProc) -> u64 {
    proc_.ppid
}

#[no_mangle]
pub extern "C" fn cosi_win_proc_eprocess(proc_: &WinProc) -> target_ptr_t {
    proc_.eprocess
}

/// Process image name (ImageFileName). Must be freed with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_proc_name(proc_: &WinProc) -> *mut c_char {
    CString::new(proc_.name.clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

// ---- module list -----------------------------------------------------------

/// Get the loaded kernel module list. Free with `cosi_win_free_module_list`.
#[no_mangle]
pub extern "C" fn cosi_win_get_module_list(cpu: &mut CPUState) -> Option<Box<Vec<WinMod>>> {
    let l = win::module_list(cpu);
    if l.is_empty() {
        None
    } else {
        Some(Box::new(l))
    }
}

#[no_mangle]
pub extern "C" fn cosi_win_module_list_len(list: &Vec<WinMod>) -> usize {
    list.len()
}

#[no_mangle]
pub extern "C" fn cosi_win_module_list_get(list: &Vec<WinMod>, index: usize) -> Option<&WinMod> {
    list.get(index)
}

#[no_mangle]
pub extern "C" fn cosi_win_free_module_list(_list: Option<Box<Vec<WinMod>>>) {}

#[no_mangle]
pub extern "C" fn cosi_win_module_base(m: &WinMod) -> target_ptr_t {
    m.base
}

#[no_mangle]
pub extern "C" fn cosi_win_module_size(m: &WinMod) -> u32 {
    m.size
}

/// Module base name. Must be freed with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_module_name(m: &WinMod) -> *mut c_char {
    CString::new(m.name.clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

// ---- process parameters (cwd / image path / command line) ------------------

/// Get a process's parameters (cwd/image/cmdline). Free with cosi_win_free_proc_params.
#[no_mangle]
pub extern "C" fn cosi_win_get_proc_params(
    cpu: &mut CPUState,
    eprocess: target_ptr_t,
) -> Box<WinProcParams> {
    Box::new(win::proc_params(cpu, eprocess))
}

#[no_mangle]
pub extern "C" fn cosi_win_free_proc_params(_p: Option<Box<WinProcParams>>) {}

/// Current directory. Must be freed with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_params_cwd(p: &WinProcParams) -> *mut c_char {
    to_cstr(&p.cwd)
}

/// Full image path. Must be freed with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_params_image_path(p: &WinProcParams) -> *mut c_char {
    to_cstr(&p.image_path)
}

/// Command line. Must be freed with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_params_cmdline(p: &WinProcParams) -> *mut c_char {
    to_cstr(&p.cmdline)
}

/// File position (CurrentByteOffset) of a File handle; -1 if not a file/invalid.
#[no_mangle]
pub extern "C" fn cosi_win_file_handle_pos(
    cpu: &mut CPUState,
    eprocess: target_ptr_t,
    handle: u64,
) -> i64 {
    win::file_handle_pos(cpu, eprocess, handle).unwrap_or(-1)
}

/// Get a process's loaded user-mode modules (DLLs) by _EPROCESS pointer.
/// Reuses the WinMod accessors (cosi_win_module_*). Free with cosi_win_free_module_list.
#[no_mangle]
pub extern "C" fn cosi_win_get_dll_list(
    cpu: &mut CPUState,
    eprocess: target_ptr_t,
) -> Option<Box<Vec<WinMod>>> {
    let l = win::proc_dlls(cpu, eprocess);
    if l.is_empty() {
        None
    } else {
        Some(Box::new(l))
    }
}

// ---- handle table ----------------------------------------------------------

/// Get the open handles of a process (by _EPROCESS pointer), each resolved to
/// object type + name. Free with `cosi_win_free_handle_list`.
#[no_mangle]
pub extern "C" fn cosi_win_get_handle_list(
    cpu: &mut CPUState,
    eprocess: target_ptr_t,
) -> Option<Box<Vec<WinHandle>>> {
    let l = win::handle_list(cpu, eprocess);
    if l.is_empty() {
        None
    } else {
        Some(Box::new(l))
    }
}

#[no_mangle]
pub extern "C" fn cosi_win_handle_list_len(list: &Vec<WinHandle>) -> usize {
    list.len()
}

#[no_mangle]
pub extern "C" fn cosi_win_handle_list_get(
    list: &Vec<WinHandle>,
    index: usize,
) -> Option<&WinHandle> {
    list.get(index)
}

#[no_mangle]
pub extern "C" fn cosi_win_free_handle_list(_list: Option<Box<Vec<WinHandle>>>) {}

#[no_mangle]
pub extern "C" fn cosi_win_handle_value(h: &WinHandle) -> u32 {
    h.handle
}

#[no_mangle]
pub extern "C" fn cosi_win_handle_object_header(h: &WinHandle) -> target_ptr_t {
    h.object_header
}

#[no_mangle]
pub extern "C" fn cosi_win_handle_access(h: &WinHandle) -> u32 {
    h.granted_access
}

/// Handle's object type name (e.g. "File", "Key"). Free with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_handle_type(h: &WinHandle) -> *mut c_char {
    CString::new(h.type_name.clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// Handle's object name (may be empty). Free with `free_cosi_str`.
#[no_mangle]
pub extern "C" fn cosi_win_handle_name(h: &WinHandle) -> *mut c_char {
    CString::new(h.object_name.clone())
        .ok()
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
