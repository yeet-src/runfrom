/* vmlinux.h dumped from a recent kernel emits a block of kfunc/ksym
 * prototypes (e.g. bpf_stream_vprintk) that collide with the ones in an
 * older bundled bpf_helpers.h. We call no kfuncs, so suppress that block
 * — bpf_helpers.h supplies every helper we use. */
#define BPF_NO_KFUNC_PROTOTYPES

/* The bpftool-generated vmlinux.h emits forward declarations the kernel
 * BTF dump can't fully resolve, which clang flags under -Wall. Harmless
 * — silence them for this header alone, leaving -Wall live below. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "vmlinux.h"
#pragma clang diagnostic pop
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* runfrom — record every successful exec on the box and snapshot where the
 * new program came from. The hook is the BTF tracepoint sched_process_exec,
 * which fires once the binary is loaded and committed but while the task is
 * still the one that called execve — so process context is the exec'd
 * program and bprm carries the facts we want: the path it was loaded from,
 * the credentials it now runs under, and the inode behind it.
 *
 * The kernel side only snapshots; all judgement (ephemeral dir, fileless,
 * privilege escalation) is JavaScript. Three facts make those calls:
 *   - bprm->filename     the path passed to execve (absolute → full path)
 *   - bprm->cred uid/euid the identity the program now runs under; euid != uid
 *                         is a setuid/privilege transition
 *   - file inode i_nlink  link count of the backing file; 0 means the code
 *                         has no name on disk — a memfd or already-unlinked
 *                         binary, i.e. a fileless exec */

struct exec_event {
    __u64 ts;            /* bpf_ktime_get_ns at the exec */
    __u32 pid;           /* tgid of the exec'd process */
    __u32 ppid;          /* tgid of the parent that spawned it */
    __u32 uid;           /* real uid the program runs under (the launcher) */
    __u32 euid;          /* effective uid after exec; != uid means escalation */
    __u32 nlink;         /* link count of the exec'd inode; 0 = fileless */
    __u32 secure;        /* kernel secureexec bit: privilege boundary crossed */
    char  comm[16];      /* exec'd program name */
    char  pcomm[16];     /* parent process name */
    char  filename[256]; /* path execve was given */
};

/* Force the verifier/BTF to retain `struct exec_event` so the daemon can
 * lift ring-buffer records into typed JS objects by name. */
__attribute__((used)) static const struct exec_event __exec_event_anchor;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    struct exec_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->ts = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    BPF_CORE_READ_STR_INTO(&e->pcomm, task, real_parent, comm);

    /* The credentials in bprm are the ones being installed for the new
     * program: uid stays the launcher's real uid, euid takes the setuid
     * target — so euid != uid is exactly a privilege transition. Reading
     * them off bprm (not the live task) is correct regardless of whether
     * commit_creds has already run by the time this tracepoint fires. */
    e->uid = BPF_CORE_READ(bprm, cred, uid.val);
    e->euid = BPF_CORE_READ(bprm, cred, euid.val);
    e->secure = BPF_CORE_READ_BITFIELD_PROBED(bprm, secureexec);
    e->nlink = BPF_CORE_READ(bprm, file, f_inode, i_nlink);

    const char *fn = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), fn);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
