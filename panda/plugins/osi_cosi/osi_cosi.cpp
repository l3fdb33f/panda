/*!
 * @file osi_cosi.cpp
 * @brief Bridge: expose COSI's build-agnostic Win10/11 introspection through
 * PANDA's generic `osi` provider interface, so unmodified osi-dependent plugins
 * work on Windows 10/11. Registers the osi on_get_* callbacks and fills
 * OsiProc/OsiThread/OsiModule from cosi's `cosi_win_*` FFI (resolved via dlsym
 * from the already-loaded cosi plugin).
 *
 * Load order: `-panda cosi:profile=...  -panda osi  -panda osi_cosi`
 */
#include <cstdint>
#include <cstring>
#include <dlfcn.h>
#include <glib.h>

extern "C" {
#include "panda/plugin.h"
}

#include "osi/osi_types.h"
#include "osi/osi_ext.h"
#include "osi/os_intro.h"

// ---- cosi FFI (resolved at init via dlsym on the cosi plugin handle) --------
static target_ptr_t (*c_cur_eproc)(CPUState *);
static void *(*c_cur_proc)(CPUState *);
static void *(*c_proc_at)(CPUState *, target_ptr_t);
static uint64_t (*c_proc_pid)(void *);
static uint64_t (*c_proc_ppid)(void *);
static char *(*c_proc_name)(void *);
static target_ptr_t (*c_proc_eproc)(void *);
static void (*c_free_proc)(void *);
static void *(*c_get_proc_list)(CPUState *);
static uintptr_t (*c_proc_list_len)(void *);
static void *(*c_proc_list_get)(void *, uintptr_t);
static void (*c_free_proc_list)(void *);
static uint64_t (*c_cur_tid)(CPUState *);
static void *(*c_get_mod_list)(CPUState *);
static void *(*c_get_dll_list)(CPUState *, target_ptr_t);
static uintptr_t (*c_mod_list_len)(void *);
static void *(*c_mod_list_get)(void *, uintptr_t);
static target_ptr_t (*c_mod_base)(void *);
static uint32_t (*c_mod_size)(void *);
static char *(*c_mod_name)(void *);
static void (*c_free_mod_list)(void *);
static void (*c_free_str)(char *);

// Take ownership of a cosi-allocated string into a g_malloc'd one (osi frees
// with g_free). Frees the cosi string.
static char *dup_cosi(char *s) {
    char *r = g_strdup(s ? s : "");
    if (s) {
        c_free_str(s);
    }
    return r;
}

static void fill_proc(OsiProc *p, void *wp) {
    memset(p, 0, sizeof(*p));
    p->taskd = c_proc_eproc(wp);
    p->pid = (target_pid_t)c_proc_pid(wp);
    p->ppid = (target_pid_t)c_proc_ppid(wp);
    p->name = dup_cosi(c_proc_name(wp));
}

static void append_modules(GArray *out, void *list) {
    uintptr_t n = c_mod_list_len(list);
    for (uintptr_t i = 0; i < n; i++) {
        void *wm = c_mod_list_get(list, i);
        OsiModule m;
        memset(&m, 0, sizeof(m));
        m.modd = c_mod_base(wm);
        m.base = c_mod_base(wm);
        m.size = c_mod_size(wm);
        m.name = dup_cosi(c_mod_name(wm));
        m.file = g_strdup(m.name);
        g_array_append_val(out, m);
    }
}

// ---- osi provider callbacks -------------------------------------------------

void on_get_current_process(CPUState *cpu, OsiProc **out) {
    void *wp = c_cur_proc(cpu);
    if (!wp) {
        *out = NULL;
        return;
    }
    OsiProc *p = (OsiProc *)g_malloc0(sizeof(OsiProc));
    fill_proc(p, wp);
    c_free_proc(wp);
    *out = p;
}

void on_get_process(CPUState *cpu, const OsiProcHandle *h, OsiProc **out) {
    void *wp = c_proc_at(cpu, h->taskd);
    OsiProc *p = (OsiProc *)g_malloc0(sizeof(OsiProc));
    fill_proc(p, wp);
    p->taskd = h->taskd;
    c_free_proc(wp);
    *out = p;
}

void on_get_processes(CPUState *cpu, GArray **out) {
    if (*out == NULL) {
        *out = g_array_sized_new(false, false, sizeof(OsiProc), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osiproc_contents);
    }
    void *list = c_get_proc_list(cpu);
    if (!list) {
        return;
    }
    uintptr_t n = c_proc_list_len(list);
    for (uintptr_t i = 0; i < n; i++) {
        OsiProc cur;
        fill_proc(&cur, c_proc_list_get(list, i));
        g_array_append_val(*out, cur);
    }
    c_free_proc_list(list);
}

void on_get_current_process_handle(CPUState *cpu, OsiProcHandle **out) {
    OsiProcHandle *h = (OsiProcHandle *)g_malloc0(sizeof(OsiProcHandle));
    h->taskd = c_cur_eproc(cpu);
    h->asid = 0;
    *out = h;
}

void on_get_process_pid(CPUState *cpu, const OsiProcHandle *h, target_pid_t *out) {
    void *wp = c_proc_at(cpu, h->taskd);
    *out = (target_pid_t)c_proc_pid(wp);
    c_free_proc(wp);
}

void on_get_process_ppid(CPUState *cpu, const OsiProcHandle *h, target_pid_t *out) {
    void *wp = c_proc_at(cpu, h->taskd);
    *out = (target_pid_t)c_proc_ppid(wp);
    c_free_proc(wp);
}

void on_get_current_thread(CPUState *cpu, OsiThread **out) {
    OsiThread *t = (OsiThread *)g_malloc0(sizeof(OsiThread));
    void *wp = c_cur_proc(cpu);
    t->pid = wp ? (target_pid_t)c_proc_pid(wp) : 0;
    if (wp) {
        c_free_proc(wp);
    }
    t->tid = (target_pid_t)c_cur_tid(cpu);
    *out = t;
}

void on_get_modules(CPUState *cpu, GArray **out) {
    if (*out == NULL) {
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 128);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }
    void *list = c_get_mod_list(cpu);
    if (!list) {
        return;
    }
    append_modules(*out, list);
    c_free_mod_list(list);
}

void on_get_mappings(CPUState *cpu, OsiProc *p, GArray **out) {
    if (*out == NULL) {
        *out = g_array_sized_new(false, false, sizeof(OsiModule), 64);
        g_array_set_clear_func(*out, (GDestroyNotify)free_osimodule_contents);
    }
    void *list = c_get_dll_list(cpu, p->taskd);
    if (!list) {
        return;
    }
    append_modules(*out, list); // per-proc DLLs reuse the WinMod accessors
    c_free_mod_list(list);
}

// ---- bootstrap --------------------------------------------------------------

#define RESOLVE(var, sym)                                                      \
    do {                                                                       \
        *(void **)(&var) = dlsym(cosi, sym);                                   \
        if (!var) {                                                            \
            fprintf(stderr, "osi_cosi: cosi symbol missing: %s\n", sym);       \
            return false;                                                      \
        }                                                                      \
    } while (0)

extern "C" bool init_plugin(void *self) {
    panda_require("osi");

    void *cosi = panda_get_plugin_by_name("cosi");
    if (!cosi) {
        fprintf(stderr,
                "osi_cosi: cosi plugin not loaded. Load it first, e.g.\n"
                "  -panda cosi:profile=<isf.json.xz> -panda osi -panda osi_cosi\n");
        return false;
    }

    RESOLVE(c_cur_eproc, "cosi_win_current_eprocess");
    RESOLVE(c_cur_proc, "cosi_win_current_proc");
    RESOLVE(c_proc_at, "cosi_win_proc_at");
    RESOLVE(c_proc_pid, "cosi_win_proc_pid");
    RESOLVE(c_proc_ppid, "cosi_win_proc_ppid");
    RESOLVE(c_proc_name, "cosi_win_proc_name");
    RESOLVE(c_proc_eproc, "cosi_win_proc_eprocess");
    RESOLVE(c_free_proc, "cosi_win_free_proc");
    RESOLVE(c_get_proc_list, "cosi_win_get_proc_list");
    RESOLVE(c_proc_list_len, "cosi_win_proc_list_len");
    RESOLVE(c_proc_list_get, "cosi_win_proc_list_get");
    RESOLVE(c_free_proc_list, "cosi_win_free_proc_list");
    RESOLVE(c_cur_tid, "cosi_win_current_tid");
    RESOLVE(c_get_mod_list, "cosi_win_get_module_list");
    RESOLVE(c_get_dll_list, "cosi_win_get_dll_list");
    RESOLVE(c_mod_list_len, "cosi_win_module_list_len");
    RESOLVE(c_mod_list_get, "cosi_win_module_list_get");
    RESOLVE(c_mod_base, "cosi_win_module_base");
    RESOLVE(c_mod_size, "cosi_win_module_size");
    RESOLVE(c_mod_name, "cosi_win_module_name");
    RESOLVE(c_free_mod_list, "cosi_win_free_module_list");
    RESOLVE(c_free_str, "free_cosi_str");

    PPP_REG_CB("osi", on_get_current_process, on_get_current_process);
    PPP_REG_CB("osi", on_get_process, on_get_process);
    PPP_REG_CB("osi", on_get_processes, on_get_processes);
    PPP_REG_CB("osi", on_get_current_process_handle, on_get_current_process_handle);
    PPP_REG_CB("osi", on_get_process_pid, on_get_process_pid);
    PPP_REG_CB("osi", on_get_process_ppid, on_get_process_ppid);
    PPP_REG_CB("osi", on_get_current_thread, on_get_current_thread);
    PPP_REG_CB("osi", on_get_modules, on_get_modules);
    PPP_REG_CB("osi", on_get_mappings, on_get_mappings);

    fprintf(stderr, "osi_cosi: registered as the Windows OSI provider (via cosi)\n");
    return true;
}

extern "C" void uninit_plugin(void *self) {}
