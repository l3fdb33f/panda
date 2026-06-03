//! Windows syscall tracer (panda-plus Win10/11 fork) — the COSI + syscalls2
//! synthesis. On each syscall entry it prints the calling process (pid/name via
//! COSI), the syscall name + arg names (from syscalls2's loaded SSDT, e.g. the
//! generated Win11 26100 table), and resolves HANDLE arguments to their object
//! type + name via COSI's handle table walk.
//!
//! syscalls2 has no in-kernel metadata on Windows (unlike Linux), so the name +
//! arg-type info comes from syscalls2's `get_syscall_info(callno)` for the
//! active profile (selected via `syscalls2:load-os=windows-64-1{0,1}`).

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicU64, Ordering};

use panda::plugins::syscalls2::Syscalls2Callbacks;
use panda::prelude::*;
use panda::{plugin_import, PppCallback};

/// Mirror of syscalls2's `syscall_info_t` (syscalls2_info.h).
#[repr(C)]
pub struct SyscallInfo {
    pub no: i32,
    pub name: *const c_char,
    pub nargs: i32,
    pub argt: *const u32,
    pub argsz: *const u8,
    pub argn: *const *const c_char,
    pub argtn: *const *const c_char,
    pub noreturn: bool,
}

plugin_import! {
    static SYSCALLS2: Syscalls2Info = extern "syscalls2" {
        fn get_syscall_info(callno: u32) -> Option<&'static SyscallInfo>;
    };
}

static TRACED: AtomicU64 = AtomicU64::new(0);
/// Bound the trace volume (TCG + log size); raise if you need more.
const MAX_TRACE: u64 = 400;

static LAST_PID: AtomicU64 = AtomicU64::new(u64::MAX);
static SWITCHES: AtomicU64 = AtomicU64::new(0);
const MAX_SWITCHES: u64 = 80;

/// Register a process-switch notifier on ASID (CR3) change. Logs each time the
/// scheduled process actually changes (build-agnostic, via COSI current process).
pub fn init_proc_switch() {
    let cb = panda::Callback::new();
    cb.asid_changed(move |cpu: &mut CPUState, _old, _new| {
        if !crate::WIN_DUMPED.load(Ordering::SeqCst)
            || SWITCHES.load(Ordering::Relaxed) >= MAX_SWITCHES
        {
            return false;
        }
        if let Some(e) = crate::win::current_eprocess(cpu) {
            let (pid, name) = crate::win::proc_pid_name(cpu, e);
            if pid != 0 && LAST_PID.swap(pid, Ordering::Relaxed) != pid {
                SWITCHES.fetch_add(1, Ordering::Relaxed);
                println!("[procswitch] -> pid={} {} (eproc={:#x})", pid, name, e);
            }
        }
        false
    });
}

unsafe fn cstr_at(arr: *const *const c_char, i: usize) -> String {
    if arr.is_null() {
        return String::new();
    }
    let p = *arr.add(i);
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// One-shot validation that the generic OSI interface routes osi -> osi_cosi ->
/// cosi: calls the osi *consumer* API and prints what comes back. Requires the
/// `osi` and `osi_cosi` plugins to be loaded.
pub fn osi_selftest(cpu: &mut CPUState) {
    use panda::plugins::osi::OSI;
    println!("[osi-selftest] routing through osi -> osi_cosi -> cosi ...");
    match OSI.get_current_process(cpu as *mut CPUState) {
        Some(p) => {
            let name = if p.name.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(p.name) }.to_string_lossy().into_owned()
            };
            println!(
                "[osi-selftest] osi.get_current_process -> pid={} ppid={} name={:?}",
                p.pid, p.ppid, name
            );
        }
        None => println!("[osi-selftest] osi.get_current_process -> None"),
    }
    let procs = OSI.get_processes(cpu as *mut CPUState);
    println!("[osi-selftest] osi.get_processes -> {} procs:", procs.len());
    for p in procs.iter().take(10) {
        let name = if p.name.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(p.name) }.to_string_lossy().into_owned()
        };
        println!("    pid={} ppid={} {}", p.pid, p.ppid, name);
    }
}

/// Register the per-syscall tracer. Active only once the OSI dump has primed the
/// kernel base (WIN_DUMPED) and only for Windows guests.
pub fn init() {
    println!("[strace] Windows syscall tracer registered");
    let cb = PppCallback::new();
    cb.on_all_sys_enter(move |cpu: &mut CPUState, _pc, callno| {
        if !crate::WIN_DUMPED.load(Ordering::SeqCst) {
            return; // kernel base not yet resolved / not in a good context
        }
        if TRACED.load(Ordering::Relaxed) >= MAX_TRACE {
            return;
        }

        let info = match SYSCALLS2.get_syscall_info(callno as u32) {
            Some(i) => i,
            None => return,
        };
        let name = if info.name.is_null() {
            "?".to_owned()
        } else {
            unsafe { CStr::from_ptr(info.name) }
                .to_string_lossy()
                .into_owned()
        };

        let base = crate::win::kernel_base(cpu);
        let (eproc, dtb) = match crate::win::current_eproc_and_dtb(cpu) {
            Some(x) => x,
            None => return,
        };
        let (pid, pname) = crate::win::proc_pid_name(cpu, eproc);

        // Windows x64 syscall ABI at the SYSCALL instruction: arg0=R10, arg1=RDX,
        // arg2=R8, arg3=R9 (RCX is clobbered by SYSCALL). Stack args (4+) omitted.
        const REG_IDX: [usize; 4] = [10, 2, 8, 9];
        let nargs = info.nargs.max(0) as usize;
        let mut parts: Vec<String> = Vec::new();
        for i in 0..nargs.min(4) {
            let val = crate::win::reg(cpu, REG_IDX[i]);
            let aname = unsafe { cstr_at(info.argn, i) };
            let label = if aname.is_empty() {
                format!("arg{}", i)
            } else {
                aname
            };
            // The generator stores "n/a" in argtn, so detect handle args by name
            // (PortHandle/FileHandle/KeyHandle/Handle/...). handle_to_object is
            // self-validating (returns None for pseudo-handles, pointers, scalars).
            if label.contains("Handle") {
                if let Some((t, n)) = crate::win::handle_to_object(cpu, base, dtb, eproc, val) {
                    if n.is_empty() {
                        parts.push(format!("{}={:#x} -> {}", label, val, t));
                    } else {
                        parts.push(format!("{}={:#x} -> {} {:?}", label, val, t, n));
                    }
                    continue;
                }
            }
            parts.push(format!("{}={:#x}", label, val));
        }
        let more = if nargs > 4 { ", ..." } else { "" };
        TRACED.fetch_add(1, Ordering::Relaxed);
        println!(
            "[strace pid={} {}] {}({}{})",
            pid,
            pname,
            name,
            parts.join(", "),
            more
        );
    });
}
