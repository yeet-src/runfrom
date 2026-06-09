/* runfrom data layer — turn raw exec_event records from the kernel into
 * normalized execs and aggregate them by the process that spawned them. The
 * eBPF side (runfrom.bpf.c) fires once per successful exec via the
 * sched_process_exec tracepoint; this module judges each exec — where it ran
 * from, whether it left no file behind, whether it gained privilege — and
 * groups execs under their parent. Nothing here knows about colors, columns,
 * or terminals; main.js and dump.js share it. */

import { RingBuf } from "yeet:bpf";
import bpf from "./runfrom.bpf.o";

/* Directory prefixes that hold no trustworthy code: world-writable and
 * wiped on reboot. A binary executed from here is the classic drop-and-run
 * pattern — not proof of trouble, but exactly the provenance worth a look.
 * Order matters: the more specific prefix wins (/var/tmp before /var). */
const EPHEMERAL = [
  { prefix: "/dev/shm/", tag: "shm" },
  { prefix: "/var/tmp/", tag: "tmp" },
  { prefix: "/tmp/", tag: "tmp" },
];

function dirOf(path) {
  const i = path.lastIndexOf("/");
  return i <= 0 ? path.slice(0, i + 1) || "/" : path.slice(0, i);
}

/* Where the executed code lives, by its path alone. "ephemeral" is the one
 * that matters — code running from a scratch dir anyone can write. */
export function classifyPath(path) {
  if (!path) return "anon"; /* execveat(AT_EMPTY_PATH): no path, fd-only exec */
  if (path[0] !== "/") return "relative";
  for (const e of EPHEMERAL) if (path.startsWith(e.prefix)) return e.tag;
  return "system";
}

export function normalize(e) {
  const path = e.filename || "";
  const scope = classifyPath(path);
  const uid = e.uid >>> 0;
  const euid = e.euid >>> 0;
  const nlink = e.nlink >>> 0;

  const ephemeral = scope === "tmp" || scope === "shm";
  /* nlink 0 means the running code has no name on disk: a memfd image or a
   * binary unlinked before exec — there is nothing left to inspect later. */
  const fileless = nlink === 0;
  const escalated = euid !== uid;

  return {
    wall: Date.now(),
    pid: e.pid >>> 0,
    ppid: e.ppid >>> 0,
    uid,
    euid,
    nlink,
    secure: !!(e.secure >>> 0),
    comm: e.comm || "?",
    pcomm: e.pcomm || "?",
    path,
    dir: path ? dirOf(path) : "",
    scope,
    ephemeral,
    fileless,
    escalated,
    toRoot: escalated && euid === 0,
    flagged: ephemeral || fileless || escalated,
  };
}

const RECENT_CAP = 200;

/* Rolling aggregate of execs, grouped parent -> executed binary. The
 * renderer reads snapshot()s of this; dump.js bypasses it and streams the
 * raw normalized execs instead. */
export class Tracker {
  constructor() {
    this.parents = new Map();
    this.bins = new Set();
    this.recent = [];
    this.totals = { execs: 0, ephemeral: 0, fileless: 0, escalated: 0 };
  }

  add(c) {
    this.totals.execs++;
    if (c.ephemeral) this.totals.ephemeral++;
    if (c.fileless) this.totals.fileless++;
    if (c.escalated) this.totals.escalated++;
    if (c.path) this.bins.add(c.path);

    this.recent.push(c);
    if (this.recent.length > RECENT_CAP) this.recent.shift();

    const pkey = `${c.ppid}/${c.pcomm}`;
    let p = this.parents.get(pkey);
    if (!p) {
      p = {
        ppid: c.ppid,
        pcomm: c.pcomm,
        first: c.wall,
        last: c.wall,
        total: 0,
        ephemeral: 0,
        fileless: 0,
        escalated: 0,
        bins: new Map(),
      };
      this.parents.set(pkey, p);
    }
    p.last = c.wall;
    p.total++;
    if (c.ephemeral) p.ephemeral++;
    if (c.fileless) p.fileless++;
    if (c.escalated) p.escalated++;

    const bkey = c.path || `anon:${c.comm}`;
    let b = p.bins.get(bkey);
    if (!b) {
      b = {
        path: c.path,
        dir: c.dir,
        comm: c.comm,
        scope: c.scope,
        ephemeral: c.ephemeral,
        fileless: c.fileless,
        escalated: c.escalated,
        toRoot: c.toRoot,
        secure: c.secure,
        uid: c.uid,
        euid: c.euid,
        first: c.wall,
        last: c.wall,
        count: 0,
      };
      p.bins.set(bkey, b);
    }
    b.last = c.wall;
    b.count++;
    b.uid = c.uid;
    b.euid = c.euid;
    return c;
  }

  snapshot() {
    return {
      parents: [...this.parents.values()],
      recent: this.recent,
      binCount: this.bins.size,
      parentCount: this.parents.size,
      totals: this.totals,
    };
  }
}

/* Load the probe, attach tp_btf/sched_process_exec (auto-attached on start
 * by its SEC name — only network hooks need an explicit .attach), and stream
 * normalized execs to `onEvent`. Rejects with a plain Error carrying a
 * privilege hint if the daemon can't load or verify the program. */
export async function capture(onEvent, onError) {
  let control;
  try {
    control = await bpf
      .bind("events", { kind: "ringbuf", btf_struct: "exec_event" })
      .start();
  } catch (e) {
    const detail = e && (e.message || e.code) ? `${e.code ? `${e.code}: ` : ""}${e.message ?? ""}`.trim() : String(e);
    throw new Error(
      `Could not load the runfrom eBPF probe${detail ? ` (${detail})` : ""}. ` +
        "It needs a kernel with BTF and the yeet daemon running with CAP_BPF " +
        "(it loads a tp_btf probe on sched_process_exec).",
    );
  }

  const events = new RingBuf(control, "events");
  const sub = await events.subscribe(
    (rec) => onEvent(normalize(rec.exec_event ?? rec)),
    (err) => onError && onError(err),
  );

  return {
    async stop() {
      try {
        await sub.unsubscribe();
      } catch {}
      try {
        await control.stop();
      } catch {}
    },
  };
}
