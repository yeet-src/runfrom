# runfrom

> **Every exec on your box, live. Catch the ones that shouldn't be running.**

<p align="center">
  <img src="https://img.shields.io/badge/platform-Linux-1793D1" alt="Linux">
  <img src="https://img.shields.io/badge/built%20with-yeet%20%2B%20eBPF-8A2BE2" alt="yeet + eBPF">
  <img src="https://img.shields.io/badge/license-GPL--2.0-3DA639" alt="GPL-2.0">
  <a href="https://discord.gg/JxVseaAVAU"><img src="https://img.shields.io/badge/chat-Discord-5865F2" alt="Discord"></a>
</p>

![runfrom demo](assets/runfrom.gif)

**runfrom is a live exec-provenance monitor that catches every process launch system-wide and flags code running from scratch directories, binaries with no name on disk, and setuid privilege jumps.**

> [!TIP]
> The insight that makes this possible: the `tp_btf/sched_process_exec` tracepoint fires after the binary is loaded and its credentials committed, but while the task is still the one that called `execve`. One probe captures the full `{parent, program, path, identity, inode}` tuple with no polling, no ptrace, no audit daemon.

## Quick start

```sh
curl -fsSL https://yeet.cx | sh
yeet run github:yeet-src/runfrom
```
[Manual install guide](https://yeet.cx/docs/installation) · Linux only

Two more commands worth knowing:

```sh
# pipe output for one-shot reporting (auto-detects the pipe, prints a snapshot and exits)
yeet run github:yeet-src/runfrom | less -R

# raw newline-delimited JSON, one object per exec, for jq or a log pipeline
yeet run github:yeet-src/runfrom/dump.js | jq -c 'select(.ephemeral or .fileless)'
```

### Flags

**Live monitor (`main.js`)** — `yeet run github:yeet-src/runfrom`

- `--sort <flagged|execs|recent|name>` (default `flagged`) — `flagged`: most suspicious first; `execs`: most total execs; `recent`: most recently active; `name`: by parent name then ppid.
- `--interval <ms>` (default `1000`, floored at `100`) — live refresh period.
- `--secs <n>` — stop after n seconds; with `--once`, the collection window before printing (default `3`).
- `--once` — print a single snapshot and exit (automatic when output is piped).

**JSON stream (`dump.js`)** — `yeet run github:yeet-src/runfrom/dump.js` (NDJSON)

- `--secs <n>` — stop after n seconds.
- `--count <n>` — stop after n records.

## A 60-second primer on exec provenance

When a program calls `execve`, the kernel loads the new binary, sets up its credentials, and points the task at the new image. Three facts about that moment tell almost everything you need to know about whether to trust the execution:

| Fact | What the kernel records | What it means |
|------|------------------------|---------------|
| **Path** | The `filename` argument passed to `execve` | Where the code came from. `/tmp`, `/var/tmp`, and `/dev/shm` are world-writable and wiped on reboot: the drop-and-run pattern. |
| **Inode link count** | `bprm->file->f_inode->i_nlink` | `0` means the code has no name left on disk. The file was unlinked before exec (or opened via `memfd_create`). Nothing to inspect after the fact. |
| **uid vs euid** | `bprm->cred->uid` and `bprm->cred->euid` | If `euid != uid`, the binary is setuid and the process just changed identity. `euid == 0` is a jump to root. |

Traditional audit tools (auditd, syslog) tell you that an exec happened. runfrom tells you whether the code that ran had a permanent address and who it became.

**BTF (BPF Type Format)** is the machine-readable kernel struct layout embedded in `/sys/kernel/btf/vmlinux`. It lets a BPF program read `task_struct` and `linux_binprm` fields by name and have the kernel verify the offsets at load time, so the same compiled `.bpf.o` runs on any kernel version that exports BTF. This is called CO-RE (Compile Once, Run Everywhere).

A **ring buffer** (`BPF_MAP_TYPE_RINGBUF`) is a lock-free, variable-size event queue shared between kernel and userspace. The BPF program reserves a slot, fills the `exec_event` struct, and submits it; the yeet daemon drains it and hands typed records to JavaScript.

## Common use cases

Mostly security engineers and SREs who want to see what's actually running on a host in real time, and developers debugging something that launches unexpected child processes.

- Deployment script finishes. Something is still running from `/tmp`. Which parent started it?
- An alert fires for privilege escalation. You want to see the exact binary and uid chain without parsing audit logs.
- You're doing an incident retrospective and need to know whether any execs came from paths that no longer exist on disk.
- A service is misbehaving. You need to know every binary it spawned in the last 30 seconds.

## What you're looking at

The live panel has three layers.

**Header line.** A single line showing the session totals: total exec count, ephemeral exec count (red when nonzero), fileless count (red when nonzero), escalated count (orange when nonzero), distinct binary paths seen, and distinct parent processes. These are running totals since the session started, not a rolling window.

**Parent blocks.** One block per spawning process, sorted flagged-first by default (parents that launched the most suspicious execs appear at the top). Each block starts with the parent's `comm` and PID, its exec tally, and per-flag subtotals. Under it, each binary the parent launched gets one line:

```
   5×  /tmp/dropper                          uid 1000  TMP
   1×  /proc/self/fd/7                       uid 1000  FILELESS
   1×  /usr/bin/sudo                         uid 1000  →ROOT
   8×  /usr/bin/ls                           uid 1000
```

The path column is color-coded: fileless paths are red, ephemeral paths (`/tmp`, `/dev/shm`) are orange, ordinary system paths are muted slate. The badges carry the verdict:

| Badge | Meaning |
|-------|---------|
| `TMP` | Exec from `/tmp` or `/var/tmp` |
| `SHM` | Exec from `/dev/shm` |
| `FILELESS` | Inode link count is 0; no file exists to inspect |
| `→ROOT` | uid → euid 0 (setuid to root) |
| `→N` | uid → euid N (setuid to another identity) |
| `suid` | Setuid bit was set but uid and euid match (already running as that user) |

**RECENT feed.** The bottom strip shows the last several execs as they land, in chronological order newest-first. Each line is `HH:MM:SS  parent_comm ▸ path  [badge]`. This is the stream view; the parent blocks above are the aggregate view.

When output is piped (or `--once` is passed), the panel renders once to stdout and exits after a configurable collection window (default 3 seconds, set with `--secs N`).

## How it works

### The BPF side

One program, one hook:

| Hook | Type | What it captures |
|------|------|-----------------|
| `sched_process_exec` | `tp_btf` | Fires once per successful `execve`, after the binary is loaded and credentials committed, while the task is still the calling process |

The program reserves a slot in a `BPF_MAP_TYPE_RINGBUF` and fills an `exec_event` struct:

```c
struct exec_event {
    __u64 ts;            // bpf_ktime_get_ns at the exec
    __u32 pid;           // tgid of the exec'd process
    __u32 ppid;          // tgid of the parent
    __u32 uid;           // real uid (the launcher)
    __u32 euid;          // effective uid after exec
    __u32 nlink;         // inode link count; 0 = fileless
    __u32 secure;        // kernel secureexec bit
    char  comm[16];      // exec'd program name
    char  pcomm[16];     // parent process name
    char  filename[256]; // path given to execve
};
```

The BPF side only snapshots. It reads three things from `bprm` (the kernel's `linux_binprm` struct that carries exec state): the filename string, the credentials being installed, and the inode link count of the backing file. It reads parent identity from the task's `real_parent`. All judgement happens in JavaScript.

The BTF anchor (`__attribute__((used)) static const struct exec_event __exec_event_anchor`) forces the verifier to retain the struct layout in the object's BTF section so the yeet daemon can lift ring buffer records into typed JS objects by struct name.

### The JS side

| File | Role |
|------|------|
| `main.js` | Entrypoint. Live TUI (alt-screen, interval redraws) or one-shot report. Reads `--sort`, `--interval`, `--secs`, `--once` args. Auto-detects pipe mode from TTY presence. |
| `data.js` | Data layer. Loads `runfrom.bpf.o`, attaches the ring buffer, normalizes each `exec_event` into a structured exec record, and aggregates execs by parent in a `Tracker`. All flag logic lives here. |
| `dump.js` | Streaming mode. Uses the same `capture()` from `data.js` but bypasses aggregation and emits newline-delimited JSON directly to stdout. |

### The data flow

`data.js` loads `runfrom.bpf.o`, binds the `events` ring buffer with the `exec_event` BTF struct as the record type, and starts the probe. The `tp_btf/sched_process_exec` hook auto-attaches from its `SEC` name; no explicit attach call is needed for tracepoints. The yeet daemon handles the BPF load and verifier step. Each ring buffer record arrives in `data.js`'s `normalize()` function, which derives `scope` (system, tmp, shm, relative, anon), `fileless` (`nlink === 0`), `escalated` (`euid !== uid`), and `toRoot` (`escalated && euid === 0`) from the raw kernel fields, then hands the result to either the `Tracker` (live view) or direct JSON output (dump mode).

## Requirements

> [!IMPORTANT]
> Linux with BTF enabled (`/sys/kernel/btf/vmlinux` must exist, which `CONFIG_DEBUG_INFO_BTF=y` provides). This is the default on most distributions shipping a kernel from the last few years (Ubuntu 20.04+, Fedora 31+, Arch with a stock kernel).

- The yeet daemon, which loads the eBPF program. `curl -fsSL https://yeet.cx | sh` installs it.

## Honest caveats

> [!NOTE]
> What runfrom does not do, and where its view is incomplete.

- **Observe-only, not enforcement.** runfrom is a monitor. It sees every exec and flags the suspicious ones; it cannot block, kill, or throttle any process. For enforcement, you need a MAC framework (SELinux, AppArmor, Landlock) or a blocking LSM hook.
- **Exec-time snapshot only.** The fields captured (path, uid, euid, nlink) are snapped at the moment `sched_process_exec` fires. If a binary is moved or re-linked after exec, or if the process drops privileges after starting, runfrom's record reflects what was true at exec time, not afterward.
- **Fileless detection is inode-link-count based.** `nlink == 0` catches the two common patterns: a binary unlinked before exec, and exec via a `memfd_create` file descriptor. It does not catch in-memory injection into an already-running process (ptrace, `/proc/<pid>/mem` writes, JIT-generated code), because those never go through `execve` at all.
- **`/var/tmp` is flagged, `/var/` is not.** Only the three prefixes compiled into `data.js` are treated as ephemeral: `/tmp/`, `/var/tmp/`, `/dev/shm/`. A binary dropped into some other world-writable directory (a misconfigured service directory, a container overlay mount) won't get a badge.
- **Only successful execs appear.** `sched_process_exec` fires after the binary is loaded and the exec committed. A failed `execve` (missing binary, permission denied, bad ELF) never reaches this tracepoint. runfrom is an execution-provenance monitor, not a syscall auditor.
- **The `→ROOT` / `→uid` badges require running as a non-root user.** When runfrom itself is collecting as uid 0, setuid execs still appear but carry the lower-key `suid` badge instead, because from root's perspective there's no identity transition.

## Community questions

**1. Can runfrom miss an exec?**

Only successful execs reach the `sched_process_exec` tracepoint; a failed `execve` (missing binary, permission denied, bad ELF) never appears. Under extreme exec rates the 1 MB ring buffer can drop records if the consumer falls behind before it drains the queue.

**2. Will this slow down every exec on my machine?**

The BPF probe runs in the kernel fast path and does a fixed, bounded amount of work per exec: one ring buffer reserve, a handful of CO-RE reads, and a submit. There are no loops over unbounded data. The ring buffer has a 1 MB capacity and the JS subscriber drains it on each tick; if the queue fills before the subscriber catches up, new events are dropped rather than blocking the exec.

**3. Why don't I see the `→ROOT` badge when I'm running as root?**

When your effective uid is already 0, executing a setuid-root binary doesn't change your identity, so `euid != uid` is false for that exec. runfrom shows the lower-key `suid` badge instead. Run the panel (or `demo.sh`) as a regular user to see the escalation flags.

**4. Is it safe to run this on a production host?**

runfrom is read-only: the BPF program only reads kernel memory and submits ring buffer records. It cannot modify kernel state. The `tp_btf/sched_process_exec` tracepoint is a stable, well-exercised hook used by perf, bpftrace, and the kernel's own audit subsystem. The probe is detached cleanly when the yeet daemon stops or Ctrl-C is pressed.

**5. How is this different from auditd or execsnoop?**

auditd captures execve syscall events via the kernel audit subsystem, writing them to a log. execsnoop (from BCC or bpftrace) does something close to what runfrom does at the kernel level. The differences are in the surface: runfrom aggregates by parent and binary, colors and ranks the flagged paths, and exposes the same data as a live TUI and as a streaming JSON feed from the same binary without reconfiguring anything. It's not a replacement for auditd if you need tamper-resistant, signed audit logs; it's for the operator who wants to see what's running right now and whether any of it looks wrong.

## Building from source

```sh
make              # produces runfrom.bpf.o and dumps vmlinux.h from the running kernel's BTF
make clean        # removes runfrom.bpf.o and include/vmlinux.h
```

Toolchain requirements: `clang` (for BPF target compilation) and `bpftool` (to dump the running kernel's BTF into `include/vmlinux.h`). `runfrom.bpf.o` and `include/vmlinux.h` are gitignored and regenerated at build time. `include/vmlinux.h` is generated from the running kernel's BTF via `bpftool btf dump file /sys/kernel/btf/vmlinux format c`; it must match the kernel you're building on, which is why it's not checked in. `yeet run github:yeet-src/runfrom` ships a prebuilt object and skips this step entirely.

## License

The BPF program (`runfrom.bpf.c`) declares its license as `"GPL"`:

```c
char LICENSE[] SEC("license") = "GPL";
```

This is required for access to the GPL-only kernel helpers it uses.

---

Built with [yeet](https://yeet.cx/docs/?utm_source=github&utm_medium=readme&utm_campaign=runfrom), a JS runtime for writing eBPF programs on Linux machines. Join us on [discord](https://discord.gg/JxVseaAVAU?utm_source=github&utm_medium=readme&utm_campaign=runfrom).
