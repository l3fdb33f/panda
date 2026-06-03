//! Windows x64 OS-introspection walkers for COSI (panda-plus Win10/11 fork).
//!
//! COSI's original `kaslr.rs`/`structs.rs` are Linux-only (`init_task`/`task_struct`).
//! This module adds the Windows equivalents. Every kernel-struct field offset is
//! read dynamically from the loaded Volatility3 ISF, so the walkers are
//! build-agnostic across 19041 (tiny10) and 26100 (tiny11) with no hardcoded
//! offsets — the whole point of the COSI approach.
//!
//! KPTI note: at a syscall-entry callback the live CR3 is the user *shadow* page
//! table, which does NOT map ntoskrnl's global data (PsActiveProcessHead etc.).
//! So the dump is driven from a kernel-mode basic-block callback (see lib.rs):
//! during normal kernel execution CR3 is the real kernel table and a plain
//! `virtual_memory_read` reaches all kernel memory. `try_dump` validates the
//! context (kernel-pointer Flink) before committing, retrying across blocks.

use std::sync::atomic::{AtomicU64, Ordering};

use panda::mem::{physical_memory_read, virtual_memory_read};
use panda::prelude::*;
use volatility_profile::VolatilityType;

use crate::symbol_table;

/// Cached ntoskrnl base (0 = not yet determined).
static KBASE: AtomicU64 = AtomicU64::new(0);

/// QEMU x86 segment index for GS (ES=0,CS=1,SS=2,DS=3,FS=4,GS=5).
const R_GS: usize = 5;
/// Canonical kernel-half lower bound (x86-64 48-bit).
const KERNEL_MIN: u64 = 0xffff_0000_0000_0000;
/// x86-64 page-table physical-address mask (bits 12..51).
const PA_MASK: u64 = 0x000f_ffff_ffff_f000;

/// True if the loaded symbol table was generated for Windows.
pub fn is_windows() -> bool {
    symbol_table().metadata.windows.is_some()
}

// ---- raw CPU env access ----------------------------------------------------

#[inline]
fn env(cpu: &CPUState) -> &panda::sys::CPUX86State {
    // SAFETY: on i386/x86_64 targets `env_ptr` is a `*mut CPUX86State`.
    unsafe { &*(cpu.env_ptr as *const panda::sys::CPUX86State) }
}

/// Read a general-purpose register by QEMU index (RAX=0,RCX=1,RDX=2,RBX=3,
/// RSP=4,RBP=5,RSI=6,RDI=7,R8=8,...,R15=15).
pub fn reg(cpu: &CPUState, idx: usize) -> u64 {
    env(cpu).regs[idx] as u64
}

// ---- guest reads (current CR3) ---------------------------------------------

fn rd_u64(cpu: &mut CPUState, addr: target_ptr_t) -> Option<u64> {
    let v = virtual_memory_read(cpu, addr, 8).ok()?;
    Some(u64::from_le_bytes(v.try_into().ok()?))
}

fn rd_u32(cpu: &mut CPUState, addr: target_ptr_t) -> Option<u32> {
    let v = virtual_memory_read(cpu, addr, 4).ok()?;
    Some(u32::from_le_bytes(v.try_into().ok()?))
}

fn rd_u16(cpu: &mut CPUState, addr: target_ptr_t) -> Option<u16> {
    let v = virtual_memory_read(cpu, addr, 2).ok()?;
    Some(u16::from_le_bytes(v.try_into().ok()?))
}

fn rd_u8(cpu: &mut CPUState, addr: target_ptr_t) -> Option<u8> {
    Some(virtual_memory_read(cpu, addr, 1).ok()?[0])
}

fn rd_cstr(cpu: &mut CPUState, addr: target_ptr_t, max: usize) -> String {
    match virtual_memory_read(cpu, addr, max) {
        Ok(b) => {
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        }
        Err(_) => String::new(),
    }
}

/// Read a _UNICODE_STRING (Length: u16 @0, Buffer: ptr @8).
fn rd_unicode_string(cpu: &mut CPUState, us_addr: target_ptr_t) -> String {
    let len = rd_u16(cpu, us_addr).unwrap_or(0) as usize;
    if len == 0 || len > 0x400 {
        return String::new();
    }
    let buf = match rd_u64(cpu, us_addr + 8) {
        Some(b) if b != 0 => b as target_ptr_t,
        _ => return String::new(),
    };
    match virtual_memory_read(cpu, buf, len) {
        Ok(bytes) => {
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        Err(_) => String::new(),
    }
}

// ---- symbol / type helpers -------------------------------------------------

fn sym_rva(name: &str) -> Option<u64> {
    Some(symbol_table().symbol_from_name(name)?.address)
}

fn foff(ty: &str, field: &str) -> Option<target_ptr_t> {
    let t = symbol_table().type_from_name(ty)?;
    Some(t.fields.get(field)?.offset as target_ptr_t)
}

/// (bit_position, bit_length) of a bitfield member, read from the ISF.
fn bitfield(ty: &str, field: &str) -> Option<(u64, u64)> {
    let t = symbol_table().type_from_name(ty)?;
    match t.fields.get(field)?.type_val.as_ref()? {
        VolatilityType::Bitfield {
            bit_position,
            bit_length,
            ..
        } => Some((*bit_position as u64, *bit_length)),
        _ => None,
    }
}

// ---- KASLR / kernel base ---------------------------------------------------

/// Verify there's a valid PE image (MZ + 'PE\0\0') mapped at `base`.
fn is_pe_image(cpu: &mut CPUState, base: target_ptr_t) -> bool {
    match virtual_memory_read(cpu, base, 2) {
        Ok(hdr) if hdr == [0x4d, 0x5a] => {}
        _ => return false,
    }
    if let Some(e_lfanew) = rd_u32(cpu, base + 0x3c) {
        if let Ok(sig) = virtual_memory_read(cpu, base + e_lfanew as target_ptr_t, 4) {
            return sig == [0x50, 0x45, 0x00, 0x00];
        }
    }
    false
}

/// Determine the ntoskrnl base in O(1): IA32_LSTAR holds the syscall entry
/// (KiSystemCall64Shadow under KPTI, else KiSystemCall64), both inside
/// ntoskrnl. base = LSTAR - rva(entry), validated by an MZ/PE check. The PE
/// headers are mapped even under the KPTI shadow CR3, so this works from any
/// context. Returns the base, or 0 on failure.
pub fn determine_kaslr_offset(cpu: &mut CPUState) -> target_ptr_t {
    let lstar = env(cpu).lstar as target_ptr_t;
    if lstar == 0 {
        return 0;
    }
    for entry in ["KiSystemCall64Shadow", "KiSystemCall64"] {
        if let Some(rva) = sym_rva(entry) {
            let rva = rva as target_ptr_t;
            if lstar > rva {
                let base = lstar - rva;
                if is_pe_image(cpu, base) {
                    return base;
                }
            }
        }
    }
    0
}

/// ntoskrnl base, cached after first successful determination.
fn ntos_base(cpu: &mut CPUState) -> target_ptr_t {
    let cached = KBASE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached as target_ptr_t;
    }
    let b = determine_kaslr_offset(cpu);
    if b != 0 {
        KBASE.store(b as u64, Ordering::Relaxed);
    }
    b
}

fn sym_addr(base: target_ptr_t, name: &str) -> Option<target_ptr_t> {
    Some(base + sym_rva(name)? as target_ptr_t)
}

// ---- KPCR / current process ------------------------------------------------

/// Get the KPCR for the current CPU (mirrors wintrospection's get_kpcr_amd64).
pub fn get_kpcr(cpu: &mut CPUState) -> target_ptr_t {
    let kgs = env(cpu).kernelgsbase as target_ptr_t;
    let gsb = env(cpu).segs[R_GS].base as target_ptr_t;
    let self_off = foff("_KPCR", "Self").unwrap_or(0x18);
    if let Some(s) = rd_u64(cpu, kgs + self_off) {
        if s == kgs as u64 {
            return kgs;
        }
    }
    if let Some(s) = rd_u64(cpu, gsb + self_off) {
        if s == gsb as u64 {
            return gsb;
        }
    }
    if kgs >= KERNEL_MIN {
        kgs
    } else {
        gsb
    }
}

/// Current _EPROCESS via KPCR -> Prcb.CurrentThread -> KTHREAD.ApcState.Process.
pub fn current_eprocess(cpu: &mut CPUState) -> Option<target_ptr_t> {
    let kpcr = get_kpcr(cpu);
    let prcb_off = foff("_KPCR", "Prcb")?;
    let curthread_off = foff("_KPRCB", "CurrentThread")?;
    let cur_thread = rd_u64(cpu, kpcr + prcb_off + curthread_off)? as target_ptr_t;
    let apcstate_off = foff("_KTHREAD", "ApcState")?;
    let proc_off = foff("_KAPC_STATE", "Process")?;
    let eproc = rd_u64(cpu, cur_thread + apcstate_off + proc_off)? as target_ptr_t;
    Some(eproc)
}

// ---- process list ----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WinProc {
    pub eprocess: target_ptr_t,
    pub pid: u64,
    pub ppid: u64,
    pub name: String,
}

/// Walk PsActiveProcessHead -> _EPROCESS.ActiveProcessLinks.
pub fn get_process_list(cpu: &mut CPUState, base: target_ptr_t) -> Vec<WinProc> {
    let mut out = Vec::new();
    let head = match sym_addr(base, "PsActiveProcessHead") {
        Some(h) => h,
        None => return out,
    };
    let apl_off = match foff("_EPROCESS", "ActiveProcessLinks") {
        Some(o) => o,
        None => return out,
    };
    let pid_off = foff("_EPROCESS", "UniqueProcessId").unwrap_or(0);
    let ppid_off = foff("_EPROCESS", "InheritedFromUniqueProcessId").unwrap_or(0);
    let name_off = foff("_EPROCESS", "ImageFileName").unwrap_or(0);

    let mut cur = match rd_u64(cpu, head) {
        Some(v) => v as target_ptr_t,
        None => return out,
    };
    let mut guard = 0;
    while cur != head && cur != 0 && guard < 4096 {
        let eproc = cur - apl_off;
        let pid = rd_u64(cpu, eproc + pid_off).unwrap_or(0);
        let ppid = rd_u64(cpu, eproc + ppid_off).unwrap_or(0);
        let name = rd_cstr(cpu, eproc + name_off, 15);
        out.push(WinProc {
            eprocess: eproc,
            pid,
            ppid,
            name,
        });
        cur = match rd_u64(cpu, cur) {
            Some(v) => v as target_ptr_t,
            None => break,
        };
        guard += 1;
    }
    out
}

// ---- thread list (per process) --------------------------------------------

#[derive(Clone, Debug)]
pub struct WinThread {
    pub ethread: target_ptr_t,
    pub tid: u64,
}

/// Walk _EPROCESS.ThreadListHead -> _ETHREAD.ThreadListEntry.
pub fn get_thread_list(cpu: &mut CPUState, eprocess: target_ptr_t) -> Vec<WinThread> {
    let mut out = Vec::new();
    let tlh_off = match foff("_EPROCESS", "ThreadListHead") {
        Some(o) => o,
        None => return out,
    };
    let tle_off = match foff("_ETHREAD", "ThreadListEntry") {
        Some(o) => o,
        None => return out,
    };
    let cid_off = foff("_ETHREAD", "Cid").unwrap_or(0);
    let uthread_off = foff("_CLIENT_ID", "UniqueThread").unwrap_or(8);

    let head = eprocess + tlh_off;
    let mut cur = match rd_u64(cpu, head) {
        Some(v) => v as target_ptr_t,
        None => return out,
    };
    let mut guard = 0;
    while cur != head && cur != 0 && guard < 8192 {
        let ethread = cur - tle_off;
        let tid = rd_u64(cpu, ethread + cid_off + uthread_off).unwrap_or(0);
        out.push(WinThread { ethread, tid });
        cur = match rd_u64(cpu, cur) {
            Some(v) => v as target_ptr_t,
            None => break,
        };
        guard += 1;
    }
    out
}

// ---- kernel module list ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct WinMod {
    pub base: target_ptr_t,
    pub size: u32,
    pub name: String,
}

/// Walk PsLoadedModuleList -> _KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks (@offset 0).
pub fn get_module_list(cpu: &mut CPUState, base: target_ptr_t) -> Vec<WinMod> {
    let mut out = Vec::new();
    let head = match sym_addr(base, "PsLoadedModuleList") {
        Some(h) => h,
        None => return out,
    };
    let dllbase_off = foff("_KLDR_DATA_TABLE_ENTRY", "DllBase").unwrap_or(0x30);
    let size_off = foff("_KLDR_DATA_TABLE_ENTRY", "SizeOfImage").unwrap_or(0x40);
    let bname_off = foff("_KLDR_DATA_TABLE_ENTRY", "BaseDllName").unwrap_or(0x58);

    let mut cur = match rd_u64(cpu, head) {
        Some(v) => v as target_ptr_t,
        None => return out,
    };
    let mut guard = 0;
    while cur != head && cur != 0 && guard < 2048 {
        let mbase = rd_u64(cpu, cur + dllbase_off).unwrap_or(0) as target_ptr_t;
        let size = rd_u32(cpu, cur + size_off).unwrap_or(0);
        let name = rd_unicode_string(cpu, cur + bname_off);
        out.push(WinMod {
            base: mbase,
            size,
            name,
        });
        cur = match rd_u64(cpu, cur) {
            Some(v) => v as target_ptr_t,
            None => break,
        };
        guard += 1;
    }
    out
}

// ---- handle table / object resolution --------------------------------------

#[derive(Clone, Debug)]
pub struct WinHandle {
    pub handle: u32,
    pub object_header: target_ptr_t,
    pub granted_access: u32,
    pub type_name: String,
    pub object_name: String,
}

/// Resolve an _OBJECT_HEADER to (type name, object name). Type via the
/// cookie-obfuscated TypeIndex → ObTypeIndexTable → _OBJECT_TYPE.Name (Win10
/// 1709+). Object name via InfoMask/ObpInfoMaskToOffset → _OBJECT_HEADER_NAME_INFO.
fn resolve_object(cpu: &mut CPUState, base: target_ptr_t, oh: target_ptr_t) -> (String, String) {
    let ti_off = foff("_OBJECT_HEADER", "TypeIndex").unwrap_or(24);
    let im_off = foff("_OBJECT_HEADER", "InfoMask").unwrap_or(26);
    let type_index = match rd_u8(cpu, oh + ti_off) {
        Some(v) => v,
        None => return (String::new(), String::new()),
    };
    let info_mask = rd_u8(cpu, oh + im_off).unwrap_or(0);

    // De-obfuscate the type index (XOR with ObHeaderCookie and (header>>8)).
    let cookie = sym_addr(base, "ObHeaderCookie")
        .and_then(|a| rd_u8(cpu, a))
        .unwrap_or(0);
    let idx = (type_index ^ ((oh >> 8) as u8) ^ cookie) as target_ptr_t;

    let type_name = match sym_addr(base, "ObTypeIndexTable") {
        Some(tit) => {
            let type_ptr = rd_u64(cpu, tit + idx * 8).unwrap_or(0) as target_ptr_t;
            if type_ptr >= KERNEL_MIN {
                let name_off = foff("_OBJECT_TYPE", "Name").unwrap_or(16);
                rd_unicode_string(cpu, type_ptr + name_off)
            } else {
                String::new()
            }
        }
        None => String::new(),
    };

    // Object name, if a NameInfo optional header is present (InfoMask bit 0x2).
    let mut object_name = String::new();
    if info_mask & 0x2 != 0 {
        if let Some(imto) = sym_addr(base, "ObpInfoMaskToOffset") {
            let off = rd_u8(cpu, imto + (info_mask & 0x3) as target_ptr_t).unwrap_or(0) as target_ptr_t;
            if off != 0 && off <= oh {
                let ni = oh - off;
                let n_off = foff("_OBJECT_HEADER_NAME_INFO", "Name").unwrap_or(8);
                object_name = rd_unicode_string(cpu, ni + n_off);
            }
        }
    }
    // File objects carry their path in _FILE_OBJECT.FileName (the object body).
    if object_name.is_empty() && type_name == "File" {
        let body_off = foff("_OBJECT_HEADER", "Body").unwrap_or(0x30);
        let fn_off = foff("_FILE_OBJECT", "FileName").unwrap_or(0x58);
        object_name = rd_unicode_string(cpu, oh + body_off + fn_off);
    }
    (type_name, object_name)
}

/// Decode one _HANDLE_TABLE_ENTRY page (256 entries) at `page`.
fn read_handle_page(
    cpu: &mut CPUState,
    base: target_ptr_t,
    page: target_ptr_t,
    handle_base: u64,
    out: &mut Vec<WinHandle>,
) {
    let (pos, len) = bitfield("_HANDLE_TABLE_ENTRY", "ObjectPointerBits").unwrap_or((20, 44));
    let mask = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
    let ga_off = foff("_HANDLE_TABLE_ENTRY", "GrantedAccessBits").map(|_| 8).unwrap_or(8);
    for k in 0..256u64 {
        if out.len() >= 65536 {
            return;
        }
        let entry = page + (k * 16) as target_ptr_t;
        let low = match rd_u64(cpu, entry) {
            Some(v) => v,
            None => continue,
        };
        let obj_ptr_bits = (low >> pos) & mask;
        if obj_ptr_bits == 0 {
            continue; // free / empty slot
        }
        let object_header = KERNEL_MIN | (obj_ptr_bits << 4);
        let granted = rd_u32(cpu, entry + ga_off as target_ptr_t).unwrap_or(0) & 0x01ff_ffff;
        let (type_name, object_name) = resolve_object(cpu, base, object_header);
        out.push(WinHandle {
            handle: ((handle_base + k) * 4) as u32,
            object_header,
            granted_access: granted,
            type_name,
            object_name,
        });
    }
}

/// Walk a process's handle table (PspCidTable-style multi-level TableCode).
pub fn get_handle_list(cpu: &mut CPUState, base: target_ptr_t, eprocess: target_ptr_t) -> Vec<WinHandle> {
    let mut out = Vec::new();
    let ot_off = match foff("_EPROCESS", "ObjectTable") {
        Some(o) => o,
        None => return out,
    };
    let object_table = match rd_u64(cpu, eprocess + ot_off) {
        Some(v) if v >= KERNEL_MIN => v as target_ptr_t,
        _ => return out,
    };
    let tc_off = foff("_HANDLE_TABLE", "TableCode").unwrap_or(8);
    let table_code = match rd_u64(cpu, object_table + tc_off) {
        Some(v) => v,
        None => return out,
    };
    let level = table_code & 0x7;
    let tbl = (table_code & !0x7u64) as target_ptr_t;

    match level {
        0 => read_handle_page(cpu, base, tbl, 0, &mut out),
        1 => {
            for i in 0..512u64 {
                if let Some(sub) = rd_u64(cpu, tbl + (i * 8) as target_ptr_t) {
                    if sub >= KERNEL_MIN {
                        read_handle_page(cpu, base, (sub & !0x7) as target_ptr_t, i * 256, &mut out);
                    }
                }
            }
        }
        _ => {
            for i in 0..512u64 {
                let mid = match rd_u64(cpu, tbl + (i * 8) as target_ptr_t) {
                    Some(v) if v >= KERNEL_MIN => (v & !0x7) as target_ptr_t,
                    _ => continue,
                };
                for j in 0..512u64 {
                    if let Some(sub) = rd_u64(cpu, mid + (j * 8) as target_ptr_t) {
                        if sub >= KERNEL_MIN {
                            read_handle_page(
                                cpu,
                                base,
                                (sub & !0x7) as target_ptr_t,
                                (i * 512 + j) * 256,
                                &mut out,
                            );
                        }
                    }
                }
            }
        }
    }
    out
}

// ---- DTB-based reads (for sys_enter / KPTI shadow-CR3 context) -------------
//
// At a syscall-entry callback the live CR3 is the user shadow table, which maps
// the current EPROCESS but NOT ntoskrnl globals / the handle table (kernel pool).
// So the strace path reads kernel memory through the process's *kernel*
// DirectoryTableBase via a manual x64 page-table walk.

fn phys_u64(pa: u64) -> Option<u64> {
    let v = physical_memory_read(pa as target_ulong, 8).ok()?;
    Some(u64::from_le_bytes(v.try_into().ok()?))
}

/// Translate a virtual address via page table `dtb` (4-level; 1G/2M large pages).
fn translate(dtb: u64, va: u64) -> Option<u64> {
    let pml4e = phys_u64((dtb & PA_MASK) + 8 * ((va >> 39) & 0x1ff))?;
    if pml4e & 1 == 0 {
        return None;
    }
    let pdpte = phys_u64((pml4e & PA_MASK) + 8 * ((va >> 30) & 0x1ff))?;
    if pdpte & 1 == 0 {
        return None;
    }
    if pdpte & 0x80 != 0 {
        return Some((pdpte & 0x000f_ffff_c000_0000) | (va & 0x3fff_ffff));
    }
    let pde = phys_u64((pdpte & PA_MASK) + 8 * ((va >> 21) & 0x1ff))?;
    if pde & 1 == 0 {
        return None;
    }
    if pde & 0x80 != 0 {
        return Some((pde & 0x000f_ffff_ffe0_0000) | (va & 0x1f_ffff));
    }
    let pte = phys_u64((pde & PA_MASK) + 8 * ((va >> 12) & 0x1ff))?;
    if pte & 1 == 0 {
        return None;
    }
    Some((pte & PA_MASK) | (va & 0xfff))
}

fn rd_bytes_dtb(dtb: u64, va: u64, len: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(len);
    let (mut cur, mut rem) = (va, len);
    while rem > 0 {
        let pa = translate(dtb, cur)?;
        let off = (cur & 0xfff) as usize;
        let chunk = std::cmp::min(rem, 0x1000 - off);
        out.extend_from_slice(&physical_memory_read(pa as target_ulong, chunk).ok()?);
        cur += chunk as u64;
        rem -= chunk;
    }
    Some(out)
}

fn rd_u64_dtb(dtb: u64, va: u64) -> Option<u64> {
    Some(u64::from_le_bytes(rd_bytes_dtb(dtb, va, 8)?.try_into().ok()?))
}
fn rd_u8_dtb(dtb: u64, va: u64) -> Option<u8> {
    Some(rd_bytes_dtb(dtb, va, 1)?[0])
}
fn rd_u32_dtb(dtb: u64, va: u64) -> Option<u32> {
    Some(u32::from_le_bytes(rd_bytes_dtb(dtb, va, 4)?.try_into().ok()?))
}
fn rd_u16_dtb(dtb: u64, va: u64) -> Option<u16> {
    Some(u16::from_le_bytes(rd_bytes_dtb(dtb, va, 2)?.try_into().ok()?))
}

/// Build a registry key path by walking the _CM_KEY_CONTROL_BLOCK parent chain
/// from a Key object's _CM_KEY_BODY (object body). Each KCB has a NameBlock
/// (_CM_NAME_CONTROL_BLOCK) holding one path component (ASCII if Compressed,
/// else UTF-16); ParentKcb links up to the hive root.
fn key_path_dtb(dtb: u64, oh: u64) -> String {
    let body = foff("_OBJECT_HEADER", "Body").unwrap_or(0x30) as u64;
    let kcb_off = foff("_CM_KEY_BODY", "KeyControlBlock").unwrap_or(8) as u64;
    let nb_off = foff("_CM_KEY_CONTROL_BLOCK", "NameBlock").unwrap_or(80) as u64;
    let pk_off = foff("_CM_KEY_CONTROL_BLOCK", "ParentKcb").unwrap_or(72) as u64;
    let hive_off = foff("_CM_KEY_CONTROL_BLOCK", "KeyHive").unwrap_or(32) as u64;
    let nlen_off = foff("_CM_NAME_CONTROL_BLOCK", "NameLength").unwrap_or(24) as u64;
    let name_off = foff("_CM_NAME_CONTROL_BLOCK", "Name").unwrap_or(26) as u64;
    let (cpos, clen) = bitfield("_CM_NAME_CONTROL_BLOCK", "Compressed").unwrap_or((0, 1));
    let cmask = if clen >= 32 { u32::MAX } else { (1u32 << clen) - 1 };

    let mut kcb = match rd_u64_dtb(dtb, oh + body + kcb_off) {
        Some(v) if v >= KERNEL_MIN => v,
        _ => return String::new(),
    };
    // Collect (component name, owning hive) child -> parent.
    let mut comps: Vec<(String, u64)> = Vec::new();
    let mut depth = 0;
    while kcb >= KERNEL_MIN && depth < 32 {
        let hive = rd_u64_dtb(dtb, kcb + hive_off).unwrap_or(0);
        let nb = rd_u64_dtb(dtb, kcb + nb_off).unwrap_or(0);
        if nb >= KERNEL_MIN {
            let nlen = rd_u16_dtb(dtb, nb + nlen_off).unwrap_or(0) as usize;
            if nlen > 0 && nlen <= 512 {
                let compressed = (rd_u32_dtb(dtb, nb).unwrap_or(0) >> cpos) & cmask != 0;
                if let Some(bytes) = rd_bytes_dtb(dtb, nb + name_off, nlen) {
                    let s = if compressed {
                        String::from_utf8_lossy(&bytes).into_owned()
                    } else {
                        let u: Vec<u16> = bytes
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        String::from_utf16_lossy(&u)
                    };
                    if !s.is_empty() {
                        comps.push((s, hive));
                    }
                }
            }
        }
        kcb = rd_u64_dtb(dtb, kcb + pk_off).unwrap_or(0);
        depth += 1;
    }
    comps.reverse();
    // A hive's mount point (in the parent hive) and that hive's root cell share a
    // name (e.g. \REGISTRY\MACHINE\SOFTWARE then the SOFTWARE hive root). Collapse
    // a consecutive duplicate ONLY when it straddles a hive boundary (different
    // KeyHive) — legitimate same-hive \Foo\Foo keys are preserved.
    let mut out: Vec<String> = Vec::with_capacity(comps.len());
    let mut prev_hive: Option<u64> = None;
    for (name, hive) in comps {
        if let Some(last) = out.last() {
            if *last == name && prev_hive != Some(hive) {
                prev_hive = Some(hive);
                continue;
            }
        }
        prev_hive = Some(hive);
        out.push(name);
    }
    out.join("\\")
}
fn rd_unicode_string_dtb(dtb: u64, us: u64) -> String {
    let len = u16::from_le_bytes(
        rd_bytes_dtb(dtb, us, 2)
            .map(|b| [b[0], b[1]])
            .unwrap_or([0, 0]),
    ) as usize;
    if len == 0 || len > 0x400 {
        return String::new();
    }
    let buf = match rd_u64_dtb(dtb, us + 8) {
        Some(b) if b != 0 => b,
        _ => return String::new(),
    };
    match rd_bytes_dtb(dtb, buf, len) {
        Some(bytes) => {
            let u: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&u)
        }
        None => String::new(),
    }
}

/// Current _EPROCESS and its kernel DirectoryTableBase (both readable at
/// sys_enter: KPCR/KTHREAD/EPROCESS are mapped under the shadow CR3).
pub fn current_eproc_and_dtb(cpu: &mut CPUState) -> Option<(target_ptr_t, u64)> {
    let eproc = current_eprocess(cpu)?;
    let dtb_off = foff("_KPROCESS", "DirectoryTableBase")?;
    let dtb = rd_u64(cpu, eproc + dtb_off)? & PA_MASK;
    Some((eproc, dtb))
}

/// Resolve an object header to (type, name) using DTB reads.
fn resolve_object_dtb(dtb: u64, base: target_ptr_t, oh: u64) -> (String, String) {
    let ti_off = foff("_OBJECT_HEADER", "TypeIndex").unwrap_or(24) as u64;
    let im_off = foff("_OBJECT_HEADER", "InfoMask").unwrap_or(26) as u64;
    let type_index = match rd_u8_dtb(dtb, oh + ti_off) {
        Some(v) => v,
        None => return (String::new(), String::new()),
    };
    let info_mask = rd_u8_dtb(dtb, oh + im_off).unwrap_or(0);
    let cookie = sym_rva("ObHeaderCookie")
        .and_then(|r| rd_u8_dtb(dtb, base as u64 + r))
        .unwrap_or(0);
    let idx = (type_index ^ ((oh >> 8) as u8) ^ cookie) as u64;
    let type_name = match sym_rva("ObTypeIndexTable") {
        Some(r) => {
            let tp = rd_u64_dtb(dtb, base as u64 + r + idx * 8).unwrap_or(0);
            if tp >= KERNEL_MIN {
                let n = foff("_OBJECT_TYPE", "Name").unwrap_or(16) as u64;
                rd_unicode_string_dtb(dtb, tp + n)
            } else {
                String::new()
            }
        }
        None => String::new(),
    };
    let mut name = String::new();
    if info_mask & 0x2 != 0 {
        if let Some(r) = sym_rva("ObpInfoMaskToOffset") {
            let off = rd_u8_dtb(dtb, base as u64 + r + (info_mask & 0x3) as u64).unwrap_or(0) as u64;
            if off != 0 && off <= oh {
                let n = foff("_OBJECT_HEADER_NAME_INFO", "Name").unwrap_or(8) as u64;
                name = rd_unicode_string_dtb(dtb, oh - off + n);
            }
        }
    }
    // File objects don't carry a name in the object header — their path lives in
    // _FILE_OBJECT.FileName (the object body, at OBJECT_HEADER + Body offset).
    if name.is_empty() && type_name == "File" {
        let body_off = foff("_OBJECT_HEADER", "Body").unwrap_or(0x30) as u64;
        let fn_off = foff("_FILE_OBJECT", "FileName").unwrap_or(0x58) as u64;
        name = rd_unicode_string_dtb(dtb, oh + body_off + fn_off);
    }
    // Key objects: build the full registry path from the _CM_KEY_BODY KCB chain.
    if name.is_empty() && type_name == "Key" {
        name = key_path_dtb(dtb, oh);
    }
    (type_name, name)
}

/// Index a process's handle table (via the kernel DTB) and return the
/// _OBJECT_HEADER VA for the given handle, or None for empty/invalid handles.
fn handle_object_header(dtb: u64, eprocess: target_ptr_t, handle: u64) -> Option<u64> {
    if handle == 0 || handle & 0x3 != 0 {
        return None; // handles are multiples of 4
    }
    let ot_off = foff("_EPROCESS", "ObjectTable")? as u64;
    let object_table = rd_u64_dtb(dtb, eprocess as u64 + ot_off)?;
    if object_table < KERNEL_MIN {
        return None;
    }
    let tc_off = foff("_HANDLE_TABLE", "TableCode")? as u64;
    let table_code = rd_u64_dtb(dtb, object_table + tc_off)?;
    let level = table_code & 0x7;
    let tbl = table_code & !0x7u64;
    let idx = handle >> 2;
    let entry = match level {
        0 => {
            if idx >= 256 {
                return None;
            }
            tbl + idx * 16
        }
        1 => {
            let (p, e) = (idx / 256, idx % 256);
            if p >= 512 {
                return None;
            }
            let sub = rd_u64_dtb(dtb, tbl + p * 8)?;
            (sub & !0x7) + e * 16
        }
        _ => {
            let p1 = idx / (256 * 512);
            let rem = idx % (256 * 512);
            let (p2, e) = (rem / 256, rem % 256);
            let mid = rd_u64_dtb(dtb, tbl + p1 * 8)?;
            let sub = rd_u64_dtb(dtb, (mid & !0x7) + p2 * 8)?;
            (sub & !0x7) + e * 16
        }
    };
    let low = rd_u64_dtb(dtb, entry)?;
    let (pos, len) = bitfield("_HANDLE_TABLE_ENTRY", "ObjectPointerBits").unwrap_or((20, 44));
    let mask = if len >= 64 { u64::MAX } else { (1u64 << len) - 1 };
    let bits = (low >> pos) & mask;
    if bits == 0 {
        return None;
    }
    Some(KERNEL_MIN | (bits << 4))
}

/// Resolve a single handle value to (object type, object name) by indexing the
/// process's handle table directly (via the kernel DTB). For strace arg display.
pub fn handle_to_object(
    cpu: &mut CPUState,
    base: target_ptr_t,
    dtb: u64,
    eprocess: target_ptr_t,
    handle: u64,
) -> Option<(String, String)> {
    let _ = cpu;
    let oh = handle_object_header(dtb, eprocess, handle)?;
    let (t, n) = resolve_object_dtb(dtb, base, oh);
    if t.is_empty() {
        None
    } else {
        Some((t, n))
    }
}

/// File position (CurrentByteOffset) for a File handle, or None if not a file.
pub fn file_handle_pos(cpu: &mut CPUState, eprocess: target_ptr_t, handle: u64) -> Option<i64> {
    let (_, dtb) = current_eproc_and_dtb(cpu)?; // kernel DTB maps all kernel pool
    let oh = handle_object_header(dtb, eprocess, handle)?;
    let body = foff("_OBJECT_HEADER", "Body")? as u64;
    let cbo = foff("_FILE_OBJECT", "CurrentByteOffset")? as u64;
    Some(rd_u64_dtb(dtb, oh + body + cbo)? as i64)
}

// ---- public convenience wrappers (used by the FFI) -------------------------

/// Cached ntoskrnl base (0 if it could not be determined).
pub fn kernel_base(cpu: &mut CPUState) -> target_ptr_t {
    ntos_base(cpu)
}

/// Full active-process list (empty if the base is unknown or the current CR3
/// does not map kernel globals — query from a kernel-mode context).
pub fn proc_list(cpu: &mut CPUState) -> Vec<WinProc> {
    let b = ntos_base(cpu);
    if b == 0 {
        Vec::new()
    } else {
        get_process_list(cpu, b)
    }
}

/// Loaded kernel module list.
pub fn module_list(cpu: &mut CPUState) -> Vec<WinMod> {
    let b = ntos_base(cpu);
    if b == 0 {
        Vec::new()
    } else {
        get_module_list(cpu, b)
    }
}

/// Per-process user-mode modules (loaded DLLs) via PEB -> Ldr ->
/// InLoadOrderModuleList. The PEB lives in the target process's user space, so
/// the list is walked through that process's own page tables (its kernel
/// DirectoryTableBase maps both its kernel and user halves); the EPROCESS fields
/// themselves are read through the current process's DTB (kernel pool).
pub fn proc_dlls(cpu: &mut CPUState, eprocess: target_ptr_t) -> Vec<WinMod> {
    let mut out = Vec::new();
    let cur_dtb = match current_eproc_and_dtb(cpu) {
        Some((_, d)) => d,
        None => return out,
    };
    let dtb_off = match foff("_KPROCESS", "DirectoryTableBase") {
        Some(o) => o as u64,
        None => return out,
    };
    let peb_off = match foff("_EPROCESS", "Peb") {
        Some(o) => o as u64,
        None => return out,
    };
    let target_dtb = match rd_u64_dtb(cur_dtb, eprocess as u64 + dtb_off) {
        Some(v) => v & PA_MASK,
        None => return out,
    };
    let peb = match rd_u64_dtb(cur_dtb, eprocess as u64 + peb_off) {
        Some(v) => v,
        None => return out,
    };
    if peb == 0 {
        return out; // System / kernel processes have no PEB
    }
    let ldr_off = foff("_PEB", "Ldr").unwrap_or(0x18) as u64;
    let list_off = foff("_PEB_LDR_DATA", "InLoadOrderModuleList").unwrap_or(0x10) as u64;
    let dllbase_off = foff("_LDR_DATA_TABLE_ENTRY", "DllBase").unwrap_or(0x30) as u64;
    let size_off = foff("_LDR_DATA_TABLE_ENTRY", "SizeOfImage").unwrap_or(0x40) as u64;
    let bname_off = foff("_LDR_DATA_TABLE_ENTRY", "BaseDllName").unwrap_or(0x58) as u64;

    let ldr = match rd_u64_dtb(target_dtb, peb + ldr_off) {
        Some(v) if v != 0 => v,
        _ => return out,
    };
    let head = ldr + list_off;
    // InLoadOrderLinks is at offset 0 of _LDR_DATA_TABLE_ENTRY, so a list node
    // pointer IS the entry base.
    let mut cur = match rd_u64_dtb(target_dtb, head) {
        Some(v) => v,
        None => return out,
    };
    let mut guard = 0;
    while cur != head && cur != 0 && guard < 1024 {
        let base = rd_u64_dtb(target_dtb, cur + dllbase_off).unwrap_or(0) as target_ptr_t;
        let size = rd_u32_dtb(target_dtb, cur + size_off).unwrap_or(0);
        let name = rd_unicode_string_dtb(target_dtb, cur + bname_off);
        out.push(WinMod { base, size, name });
        cur = match rd_u64_dtb(target_dtb, cur) {
            Some(v) => v,
            None => break,
        };
        guard += 1;
    }
    out
}

#[derive(Clone, Debug, Default)]
pub struct WinProcParams {
    pub cwd: String,
    pub image_path: String,
    pub cmdline: String,
}

/// Process parameters (current directory, full image path, command line) from
/// PEB -> ProcessParameters (_RTL_USER_PROCESS_PARAMETERS). All in user space,
/// so walked via the target process's own page tables.
pub fn proc_params(cpu: &mut CPUState, eprocess: target_ptr_t) -> WinProcParams {
    let mut p = WinProcParams::default();
    let cur_dtb = match current_eproc_and_dtb(cpu) {
        Some((_, d)) => d,
        None => return p,
    };
    let dtb_off = match foff("_KPROCESS", "DirectoryTableBase") {
        Some(o) => o as u64,
        None => return p,
    };
    let peb_off = match foff("_EPROCESS", "Peb") {
        Some(o) => o as u64,
        None => return p,
    };
    let target_dtb = match rd_u64_dtb(cur_dtb, eprocess as u64 + dtb_off) {
        Some(v) => v & PA_MASK,
        None => return p,
    };
    let peb = match rd_u64_dtb(cur_dtb, eprocess as u64 + peb_off) {
        Some(v) if v != 0 => v,
        _ => return p,
    };
    let pp_off = foff("_PEB", "ProcessParameters").unwrap_or(0x20) as u64;
    let pp = match rd_u64_dtb(target_dtb, peb + pp_off) {
        Some(v) if v != 0 => v,
        _ => return p,
    };
    // CurrentDirectory is a _CURDIR (DosPath _UNICODE_STRING at its offset 0).
    let cwd_off = foff("_RTL_USER_PROCESS_PARAMETERS", "CurrentDirectory").unwrap_or(0x38) as u64
        + foff("_CURDIR", "DosPath").unwrap_or(0) as u64;
    let img_off = foff("_RTL_USER_PROCESS_PARAMETERS", "ImagePathName").unwrap_or(0x60) as u64;
    let cmd_off = foff("_RTL_USER_PROCESS_PARAMETERS", "CommandLine").unwrap_or(0x70) as u64;
    p.cwd = rd_unicode_string_dtb(target_dtb, pp + cwd_off);
    p.image_path = rd_unicode_string_dtb(target_dtb, pp + img_off);
    p.cmdline = rd_unicode_string_dtb(target_dtb, pp + cmd_off);
    p
}

/// Threads of the given process.
pub fn thread_list(cpu: &mut CPUState, eprocess: target_ptr_t) -> Vec<WinThread> {
    get_thread_list(cpu, eprocess)
}

/// (pid, ImageFileName) for a process (read via current CR3; EPROCESS is mapped).
pub fn proc_pid_name(cpu: &mut CPUState, eprocess: target_ptr_t) -> (u64, String) {
    let pid = foff("_EPROCESS", "UniqueProcessId")
        .and_then(|o| rd_u64(cpu, eprocess + o))
        .unwrap_or(0);
    let name = foff("_EPROCESS", "ImageFileName")
        .map(|o| rd_cstr(cpu, eprocess + o, 15))
        .unwrap_or_default();
    (pid, name)
}

/// Current thread id (KPCR -> Prcb.CurrentThread -> _ETHREAD.Cid.UniqueThread).
pub fn current_tid(cpu: &mut CPUState) -> Option<u64> {
    let kpcr = get_kpcr(cpu);
    let prcb = foff("_KPCR", "Prcb")?;
    let ct = foff("_KPRCB", "CurrentThread")?;
    let cur_thread = rd_u64(cpu, kpcr + prcb + ct)? as target_ptr_t;
    let cid = foff("_ETHREAD", "Cid")?;
    let ut = foff("_CLIENT_ID", "UniqueThread")?;
    rd_u64(cpu, cur_thread + cid + ut)
}

/// WinProc (pid/ppid/name) for a given _EPROCESS pointer.
pub fn proc_at(cpu: &mut CPUState, eprocess: target_ptr_t) -> WinProc {
    let (pid, name) = proc_pid_name(cpu, eprocess);
    let ppid = foff("_EPROCESS", "InheritedFromUniqueProcessId")
        .and_then(|o| rd_u64(cpu, eprocess + o))
        .unwrap_or(0);
    WinProc {
        eprocess,
        pid,
        ppid,
        name,
    }
}

/// Current process as a WinProc (eprocess + pid + ppid + name), or None.
pub fn current_proc(cpu: &mut CPUState) -> Option<WinProc> {
    let e = current_eprocess(cpu)?;
    Some(proc_at(cpu, e))
}

/// Open handles of the given process, resolved to object type + name.
pub fn handle_list(cpu: &mut CPUState, eprocess: target_ptr_t) -> Vec<WinHandle> {
    let b = ntos_base(cpu);
    if b == 0 {
        Vec::new()
    } else {
        get_handle_list(cpu, b, eprocess)
    }
}

// ---- one-shot diagnostic dump (live validation) ----------------------------

/// Attempt the full OSI dump. Returns true only if it ran in a valid kernel-CR3
/// context (PsActiveProcessHead resolves to a kernel pointer and the process
/// list is non-empty); the caller keeps retrying across blocks until then.
pub fn try_dump(cpu: &mut CPUState) -> bool {
    let base = ntos_base(cpu);
    if base == 0 {
        return false;
    }
    // Context probe: PsActiveProcessHead.Flink must be a canonical kernel ptr.
    let head = match sym_addr(base, "PsActiveProcessHead") {
        Some(h) => h,
        None => return false,
    };
    let flink = match rd_u64(cpu, head) {
        Some(v) => v,
        None => return false,
    };
    if flink < KERNEL_MIN {
        return false;
    }

    println!("\n========== [cosi-win] OSI dump ==========");
    println!("[cosi-win] ntoskrnl base = {:#x}", base);

    if let Some(e) = current_eprocess(cpu) {
        println!("[cosi-win] current _EPROCESS = {:#x}", e);
        let threads = get_thread_list(cpu, e);
        let tids: Vec<u64> = threads.iter().take(12).map(|t| t.tid).collect();
        println!(
            "[cosi-win] current process has {} threads; first tids = {:?}",
            threads.len(),
            tids
        );
        let handles = get_handle_list(cpu, base, e);
        println!("[cosi-win] current process has {} handles:", handles.len());
        for h in handles.iter().take(24) {
            let named = if h.object_name.is_empty() {
                String::new()
            } else {
                format!(" name={:?}", h.object_name)
            };
            println!(
                "    handle={:#06x} type={:<14} access={:#x}{}",
                h.handle, h.type_name, h.granted_access, named
            );
        }
        let dlls = proc_dlls(cpu, e);
        println!("[cosi-win] current process has {} loaded DLLs:", dlls.len());
        for m in dlls.iter().take(20) {
            println!("    base={:#x} size={:#x} {}", m.base, m.size, m.name);
        }
        let pp = proc_params(cpu, e);
        println!(
            "[cosi-win] cwd={:?} image={:?} cmdline={:?}",
            pp.cwd, pp.image_path, pp.cmdline
        );
        if let Some(h) = handles.iter().find(|h| h.type_name == "File") {
            if let Some(pos) = file_handle_pos(cpu, e, h.handle as u64) {
                println!(
                    "[cosi-win] file handle {:#x} {:?} CurrentByteOffset={:#x}",
                    h.handle, h.object_name, pos
                );
            }
        }
    }

    let procs = get_process_list(cpu, base);
    println!("[cosi-win] process list ({} procs):", procs.len());
    for p in procs.iter().take(80) {
        println!(
            "    pid={:>6} ppid={:>6} {:<16} eproc={:#x}",
            p.pid, p.ppid, p.name, p.eprocess
        );
    }

    // Handle/object resolution: the System process (pid 4) always has a
    // populated handle table, so it validates the walk regardless of how early
    // the dump fires.
    if let Some(sys) = procs.iter().find(|p| p.pid == 4) {
        let handles = get_handle_list(cpu, base, sys.eprocess);
        println!("[cosi-win] System(pid 4) has {} handles:", handles.len());
        for h in handles.iter().take(24) {
            let named = if h.object_name.is_empty() {
                String::new()
            } else {
                format!(" name={:?}", h.object_name)
            };
            println!(
                "    handle={:#06x} type={:<14} access={:#x}{}",
                h.handle, h.type_name, h.granted_access, named
            );
        }
    }

    let mods = get_module_list(cpu, base);
    println!("[cosi-win] kernel modules ({}):", mods.len());
    for m in mods.iter().take(16) {
        println!("    base={:#x} size={:#x} {}", m.base, m.size, m.name);
    }
    println!("=========================================\n");

    !procs.is_empty()
}
