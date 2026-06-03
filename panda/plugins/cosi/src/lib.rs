use std::mem::size_of;
use std::sync::atomic::{AtomicBool, Ordering};

use downloader::get_symtab_name;
use panda::mem::read_guest_type;

use panda::prelude::*;

use once_cell::sync::{Lazy, OnceCell};
use volatility_profile::VolatilityJson;

#[cfg(not(feature = "ppc"))]
use panda::plugins::syscalls2::Syscalls2Callbacks;

static SYMBOL_TABLE: OnceCell<VolatilityJson> = OnceCell::new();

mod downloader;
/// Interface for other plugins to interact with
mod ffi;
mod kaslr;
mod structs;
/// Windows x64 OS-introspection walkers (build-agnostic via the loaded ISF).
mod win;
/// Windows syscall tracer (COSI + syscalls2 synthesis).
mod strace;

use kaslr::kaslr_offset;

use std::path::{Path, PathBuf};

use crate::downloader::download_symbol_table;
use crate::structs::*;

#[derive(PandaArgs)]
#[name = "cosi"]
struct Args {
    #[arg(about = "Path to a volatility 3 symbol table to use (.xz compressed json)")]
    profile: String,

    #[arg(about = "Enable the Windows syscall tracer (requires syscalls2)")]
    win_strace: bool,

    #[arg(about = "One-shot self-test of the osi->osi_cosi->cosi round-trip (requires osi+osi_cosi)")]
    osi_selftest: bool,
}

static ARGS: Lazy<Args> = Lazy::new(Args::from_panda_args);

#[allow(deprecated)]
fn symbol_table() -> &'static VolatilityJson {
    SYMBOL_TABLE.get_or_init(|| {

        let path = if ARGS.profile.is_empty() || !Path::new(&ARGS.profile).exists() {
            let name = get_symtab_name();
            let filename = if ARGS.profile.is_empty() {
                &name
            } else {
                &ARGS.profile
            };

            let home = std::env::home_dir().unwrap();
            // This part is hacky and bad, but PathBuf::push() was choking on something
            // (probably the many '.'s in the symbol table name), whereas this seems to work
            // so it's like this until I'm back from break :)
            let path_name = home.to_str().unwrap().to_owned() + "/.panda/" + filename + ".json.xz";
            let path = std::path::PathBuf::from(path_name);

            if !path.exists() {
                if !path.parent().map(Path::exists).unwrap_or(true) {
                    std::fs::create_dir_all(path.parent().unwrap())
                        .expect("Failed to create panda directory");
                }

                println!("Given symbol table not found, attempting to download...");
                match download_symbol_table(
                    path.to_str().unwrap(),
                    path.file_name().as_ref().unwrap().to_str().unwrap(),
                ) {
                    true => println!("Downloaded!"),
                    false => {
                        println!("Download failed, exiting");
                        std::process::exit(1)
                    }
                };
            }

            path
        } else {
            PathBuf::from(&ARGS.profile)
        };

        VolatilityJson::from_compressed_file(&path)
    })
}

static READY_FOR_KASLR_SEARCH: AtomicBool = AtomicBool::new(false);
/// One-shot guard for the Windows OSI validation dump.
static WIN_DUMPED: AtomicBool = AtomicBool::new(false);

#[panda::init]
fn init(_: &mut PluginHandle) -> bool {
    // Ensure symbol table is initialized
    let _ = symbol_table();

    // Windows OSI live-validation: drive the dump from a kernel-mode basic
    // block. Unlike syscall entry (KPTI shadow CR3, where ntoskrnl globals are
    // unmapped), normal kernel execution runs with the real kernel CR3, so a
    // plain virtual_memory_read reaches all kernel memory. try_dump() probes the
    // context and only commits once PsActiveProcessHead resolves; then disables.
    //
    // The per-block callback is EXPENSIVE under TCG, so it stays disabled during
    // the long cold boot and is enabled only after the first syscall (when the
    // kernel is up); it disables itself the moment the dump succeeds.
    #[cfg(not(feature = "ppc"))]
    {
        let bb = panda::Callback::new();
        if win::is_windows() {
            bb.before_block_exec(move |cpu: &mut CPUState, _| {
                if WIN_DUMPED.load(Ordering::SeqCst) || !panda::in_kernel_mode(cpu) {
                    return;
                }
                if win::try_dump(cpu) {
                    WIN_DUMPED.store(true, Ordering::SeqCst);
                    if ARGS.osi_selftest {
                        strace::osi_selftest(cpu);
                    }
                    bb.disable();
                }
            });
            bb.disable(); // remain off until the first syscall
        }

        let first_syscall = panda::PppCallback::new();
        first_syscall.on_all_sys_enter(move |_, _, _| {
            READY_FOR_KASLR_SEARCH.store(true, Ordering::SeqCst);
            if win::is_windows() {
                bb.enable();
            }
            first_syscall.disable();
        });

        // Windows syscall tracer (COSI + syscalls2). Gated behind win_strace so
        // the per-syscall callback overhead is only paid when requested.
        if win::is_windows() && ARGS.win_strace {
            strace::init();
            strace::init_proc_switch();
        }
    }

    #[cfg(any(feature = "mips", feature = "mipsel"))] {
        structs::HWPROCID.ensure_init();
    }

    true
}

#[panda::uninit]
fn exit(_: &mut PluginHandle) {
    println!("Exiting");
}

fn current_cpu_offset(cpu: &mut CPUState) -> target_ulong {
    let symbol_table = symbol_table();

    let cpu_offset = match symbol_table.symbol_from_name("__per_cpu_offset") {
        Some(symbol) => symbol.address as target_ptr_t,
        None => return 0,
    };

    let kaslr_offset = kaslr_offset(cpu);
    let cpu_num = cpu.cpu_index as target_ptr_t;
    let offset_in_array = size_of::<target_ulong>() as target_ptr_t * cpu_num;

    let cpu_offset_ptr = kaslr_offset + cpu_offset + offset_in_array;
    let cpu_offset: target_ulong = read_guest_type(cpu, cpu_offset_ptr).unwrap();

    cpu_offset
}

/*
osi_static! {
    #[per_cpu]
    #[symbol = "current_task"]
    static CURRENT_TASK: TaskStruct;
} */

// Currently walks the process list based on task_struct->tasks,
// but some systems might instead have task_struct->next_task field
// Possibly we don't need to do all the work of locating the
/// `get_process_list` returns a `Vec` of `CosiProc`s representing all processes currently running on the system, starting from `init`
fn get_process_list(cpu: &mut CPUState) -> Option<Vec<CosiProc>> {
    let mut ret = Vec::<CosiProc>::new();
    let mut ts_current = match CosiProc::get_init_cosiproc(cpu) {
        Some(res) => res,
        None => match CosiProc::get_current_cosiproc(cpu) {
            Some(res) => {
                //println!("[debug] couldnt read init cosiproc");
                let tmp = CosiProc::new(cpu, res.taskd)?;
                tmp.get_next_process(cpu)?
            }
            None =>
            //{ println!("[debug] couldnt read current cosiproc"); return None},
            {
                return None
            }
        },
    };
    let first_addr = ts_current.addr;
    loop {
        ret.push(ts_current.clone());
        ts_current = match ts_current.get_next_process(cpu) {
            Some(next) => next,
            None => break,
        };
        if ts_current.addr == 0 || ts_current.addr == first_addr {
            break;
        }
    }
    Some(ret)
}

/// `get_process_children` returns a `Vec` of `CosiProcs` representing all the children of the process represented by a given `CosiProc`
fn get_process_children(cpu: &mut CPUState, proc: &CosiProc) -> Option<Vec<CosiProc>> {
    let mut ret = Vec::<CosiProc>::new();
    let mut ts_current = proc.get_next_child(cpu)?;

    if ts_current.mm.is_none() {
        return None;
    }

    let first_addr = ts_current.addr;
    println!("First addr: {first_addr:x} | proc_addr: {:x}", proc.addr);
    loop {
        ret.push(ts_current.clone());
        ts_current = match ts_current.get_next_sibling(cpu) {
            Some(next) => next,
            None => {
                println!("Goofed it");
                break;
            }
        };
        if ts_current.addr == 0 || ts_current.addr == first_addr {
            break;
        }
    }
    Some(ret)
}
