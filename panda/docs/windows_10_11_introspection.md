# Windows 10 & 11 (x64) record/replay + OS introspection

This fork extends PANDA's Windows support to **Windows 10 (build 19041 family,
e.g. 19044)** and **Windows 11 (build 26100, 24H2)** on x86-64, covering:

* record/replay of the live guests under TCG, and
* OS introspection (processes, threads, modules, per-process DLLs, handles,
  files, and registry keys) via the **COSI** plugin, driven by
  **Volatility 3 symbol tables (ISF)** so the walkers are *build-agnostic* — the
  same code works across kernel builds given the matching symbol table.

Unlike the legacy `wintrospection` plugin (which hardcodes per-profile struct
offsets and only reaches `windows-64-10sp0` / early Win10 1507), COSI reads every
kernel-struct field offset from the loaded ISF at runtime, so no per-build offset
tables are checked in.

---

## What's included

| Area | Plugin / file | Notes |
|------|---------------|-------|
| Windows KASLR + walkers | `panda/plugins/cosi/src/win.rs` | ntoskrnl base via `IA32_LSTAR`; EPROCESS/ETHREAD/PEB-LDR walks; handle/object, file-path, and registry-key resolution; per-process DLLs, cwd/cmdline/image-path |
| ISF loader fix | `panda/plugins/cosi/volatility_profile/src/lib.rs` | accept Windows ISF (`metadata.windows`), not just Linux |
| Windows strace | `panda/plugins/cosi/src/strace.rs` | per-syscall tracer enriched with resolved handle → object/file/key paths; process-switch logging |
| OSI provider bridge | `panda/plugins/osi_cosi/` | exposes COSI's Windows introspection through PANDA's generic `osi` interface, so unmodified osi-dependent plugins work on Win10/11 |
| Win11 syscall profile | `panda/plugins/syscalls2/` | `PROFILE_WINDOWS_11_X64` (488 `Nt*` syscalls extracted from 26100 `ntdll.dll`) |
| `-os` names | `panda/src/common.c` | accept `windows-64-10` and `windows-64-11` variants |

---

## 1. Generate a symbol table (ISF) for your guest

COSI consumes a Volatility 3 ISF (`<PDB-GUID>-<age>.json.xz`). To build one
without root or libguestfs on the host:

1. Boot the installed disk under stock QEMU+KVM with an **ephemeral overlay**
   (`-snapshot`, so the pristine image is untouched), let it settle ~100 s.
2. Dump guest memory over QMP: `dump-guest-memory <file>` (produces an ELF,
   auto-pauses the VM).
3. Run Volatility 3 against it:
   ```
   vol -f mem.elf windows.info
   ```
   `vol` (3.x) auto-detects the `ntkrnlmp` PDB GUID and downloads + builds the
   ISF from the Microsoft symbol server.

Place the resulting `<GUID>-<age>.json.xz` where COSI looks for it (see below).

> Validated tables: tiny10 = `40B8DB4F…CB89-1` (19044), tiny11 =
> `953A8DE8…C2D9-1` (26100). The two `_EPROCESS` layouts differ completely
> across builds, which is exactly why per-build symbol tables are required.

---

## 2. Run introspection (COSI)

```
panda-system-x86_64 ... \
  -os windows-64-11 \
  -panda 'cosi:profile=/path/to/<GUID>-<age>.json.xz' \
  -panda 'syscalls2:load-info=true' \
  -panda 'cosi:win_strace=true'      # optional: enriched syscall trace
```

`cosi:profile=` may be a full path to an ISF, or empty to fall back to the
auto-download / `~/.panda/<name>.json.xz` convention. With `win_strace=true`
COSI prints a Windows syscall trace where handle arguments are resolved to
object/file/registry paths, e.g.:

```
[strace pid=884 svchost.exe] NtQueryValueKey(KeyHandle=0xa68 ->
    Key "REGISTRY\MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\CONTAINERS", ...)
[strace pid=1412 svchost.exe] NtDeviceIoControlFile(FileHandle=0x3a0 -> File "\Endpoint", ...)
```

### Using existing osi-dependent plugins

COSI itself does not implement PANDA's generic `osi` provider interface; the
`osi_cosi` bridge does. Load it after `osi` (and disable osi's autoload of
`wintrospection`, which does not support these profiles):

```
-panda 'cosi:profile=...' \
-panda 'osi:disable-autoload=true' \
-panda osi_cosi
```

After this, any plugin that consumes `osi` (`get_current_process`,
`get_processes`, modules, current thread) works against the Win10/11 guest.

---

## 3. Record / replay

Record/replay is guest-OS-agnostic (it records non-deterministic inputs at the
QEMU hardware level). The guests record and replay deterministically under TCG
with `-icount`. Requirements: single vCPU (no `-smp`), IDE/MBR disk, and an
e1000 NIC if you want the `net`/`network`/`tainted_net` plugins (those operate
at the NIC/replay layer and need no OS-specific support).

Win11 (qemu64 CPU) additionally needs `+ssse3,+sse4.1,+sse4.2,+popcnt`.

### Via the C tool

```
panda-system-x86_64 -m 4096 -machine accel=tcg \
  -drive file=win.qcow2,if=ide,format=qcow2 \
  -netdev user,id=n0 -device e1000,netdev=n0 \
  -icount shift=1,sleep=off \
  -monitor stdio
# (monitor) begin_record myrec
# ... let the guest run ...
# (monitor) end_record
panda-system-x86_64 ... -replay myrec
```

### Via PyPANDA

```python
from pandare import Panda
extra = ["-machine","accel=tcg","-icount","shift=1,sleep=off",
         "-netdev","user,id=n0","-device","e1000,netdev=n0"]
# win11: extra += ["-cpu","qemu64,+ssse3,+sse4.1,+sse4.2,+popcnt"]
panda = Panda(arch="x86_64", qcow="win.qcow2", mem="4096", extra_args=extra)

@panda.queue_blocking
def drive():
    panda.record("myrec")
    # ... drive the guest ...
    panda.end_record(); panda.end_analysis()
panda.run()

panda.run_replay("myrec")   # replays deterministically to end-of-log
```

> Verified end-to-end on both guests: tiny10 replayed 3,925,817 instructions and
> tiny11 replayed 3,959,539,607 instructions with no divergence, each with a
> Python `before_block_exec` callback attached.
>
> Note: the in-tree PyPANDA needs its cffi bindings generated once with
> `python3 panda/python/core/create_panda_datatypes.py` after building.

---

## Building

`cosi` and `osi_cosi` are enabled in `panda/plugins/config.panda`. `cosi` is a
Rust plugin, so a Rust toolchain (`cargo`) must be on `PATH` at build time
(`rustup` user-local install is fine). The DWARF source-introspection plugins
(`pri_dwarf`/`dwarf2`/`pri_simple`/`pri_taint`/`pri_trace`) are disabled in the
plugin manifests because they use libdwarf APIs removed in libdwarf 0.8+/0.11;
re-enable them if your host has a compatible libdwarf.
