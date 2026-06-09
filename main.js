/* runfrom — a live "where is this code running from" panel. Every exec on
 * the box is caught in the kernel at sched_process_exec and grouped under the
 * process that spawned it, then by the binary that ran. Execs launched from a
 * world-writable scratch dir are flagged TMP / SHM, code with no name left on
 * disk (memfd or unlinked binary) gets FILELESS, and a setuid jump to another
 * identity gets →ROOT / →uid — so a process quietly running code from where
 * code shouldn't live, or gaining privilege as it does, stands out at once.
 *
 *   yeet run examples/runfrom/main.js
 *   yeet run examples/runfrom/main.js -- --sort flagged
 *   yeet run examples/runfrom/main.js -- --once --secs 5 | less -R
 *
 * Flags:
 *   --sort flagged|execs|recent|name   parent order (default flagged, then recent)
 *   --interval N                       redraw period in ms (default 1000)
 *   --secs N                           live: exit after N seconds; once: collect window
 *   --once                             collect a short window, print one report, exit
 *                                      (auto-selected when output is piped)
 */

import { Tracker, capture } from "./data.js";

const args = (typeof yeet !== "undefined" && yeet.args) || {};

/* The `tty` namespace only exists when the daemon handed us a PTY, so its
 * absence is our "we're being piped" signal — drop to a one-shot report. */
const TTY = (typeof tty !== "undefined" && tty) || null;
const ONCE = !!args.once || !TTY;
const INTERVAL = Math.max(100, Number(args.interval ?? 1000) | 0);
const SECS = args.secs != null ? Math.max(0, Number(args.secs)) : null;
const WINDOW_MS = (SECS != null ? SECS : 3) * 1000; /* once: collect before printing */

const ESC = "\x1b";
const ERASE = `${ESC}[2K`;
const at = (row, col) => `${ESC}[${row};${col}H`;

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, "");
const visLen = (s) => stripAnsi(s).length;

/* Clip a (possibly colored) line to `width` visible columns, stepping over
 * zero-width SGR escapes, re-closing color only if the line carried any. */
function clip(line, width) {
  if (visLen(line) <= width) return line;
  let out = "";
  let vis = 0;
  for (let i = 0; i < line.length && vis < width; ) {
    const esc = line[i] === "\x1b" && /^\x1b\[[0-9;]*m/.exec(line.slice(i));
    if (esc) {
      out += esc[0];
      i += esc[0].length;
    } else {
      out += line[i++];
      vis++;
    }
  }
  return out.includes("\x1b[") ? out + "\x1b[0m" : out;
}

/* Path elision keeps the meaningful tail — a long /usr/lib/.../foo collapses
 * its middle, never its basename, since the basename is what's being run. */
function fitPath(path, width) {
  if (path.length <= width) return path.padEnd(width);
  if (width <= 1) return path.slice(-width);
  const base = path.slice(path.lastIndexOf("/"));
  if (base.length >= width - 1) return ("…" + path.slice(-(width - 1))).padEnd(width);
  const head = path.slice(0, width - 1 - base.length);
  return (head + "…" + base).padEnd(width);
}

function fit(text, width, align) {
  let s = String(text ?? "");
  if (s.length > width) s = width <= 1 ? s.slice(0, width) : s.slice(0, width - 1) + "…";
  return align === "right" ? s.padStart(width) : s.padEnd(width);
}

function log(msg = "") {
  const s = String(msg);
  console.log(TTY ? s.replace(/\r?\n/g, "\r\n") + "\r" : s);
}

const red = (s) => style.fg(String(s), 248, 113, 113);
const orange = (s) => style.fg(String(s), 251, 146, 60);
const slate = (s) => style.fg(String(s), 148, 163, 184);
const dim = (s) => style.dim(String(s));
const bold = (s) => style.bold(String(s));

/* Tint a path by what it tells us: ephemeral and fileless are alerts (red /
 * orange), an ordinary system path is muted so the flagged ones pop. */
function paintPath(b, s) {
  if (b.fileless) return red(s);
  if (b.scope === "tmp" || b.scope === "shm") return orange(s);
  if (b.scope === "relative" || b.scope === "anon") return style.fg(String(s), 250, 204, 21);
  return slate(s);
}

function hhmmss(ms) {
  const d = ms != null ? new Date(ms) : new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const flagScore = (x) => x.ephemeral + x.fileless + x.escalated;

const PARENT_SORTS = {
  flagged: (a, b) => flagScore(b) - flagScore(a) || b.last - a.last,
  execs: (a, b) => b.total - a.total || b.last - a.last,
  recent: (a, b) => b.last - a.last,
  name: (a, b) => cmp(a.pcomm, b.pcomm) || a.ppid - b.ppid,
};
const SORT = PARENT_SORTS[args.sort] ? args.sort : "flagged";

const binFlag = (b) => (b.fileless ? 3 : 0) + (b.ephemeral ? 2 : 0) + (b.escalated ? 1 : 0);
const binSort = (a, b) => binFlag(b) - binFlag(a) || b.count - a.count || b.last - a.last;

function badges(b) {
  const out = [];
  if (b.fileless) out.push(red("FILELESS"));
  if (b.scope === "tmp") out.push(red("TMP"));
  if (b.scope === "shm") out.push(red("SHM"));
  if (b.toRoot) out.push(red("→ROOT"));
  else if (b.escalated) out.push(orange(`→${b.euid}`));
  else if (b.secure) out.push(dim("suid"));
  return out.join(" ");
}

function binLine(b) {
  const count = dim(`${b.count}×`.padStart(5));
  const path = paintPath(b, fitPath(b.path || `(${b.comm})`, 38));
  const who = dim(fit(`uid ${b.uid}`, 8, "left"));
  const tag = badges(b);
  return `  ${count}  ${path} ${who}${tag ? " " + tag : ""}`.replace(/\s+$/, "");
}

function parentHeader(p) {
  const title = `${bold(p.pcomm)} ${dim(p.ppid)}`;
  const tally = [
    `${p.total} ${dim("execs")}`,
    p.ephemeral ? red(`${p.ephemeral} ephemeral`) : null,
    p.fileless ? red(`${p.fileless} fileless`) : null,
    p.escalated ? orange(`${p.escalated} escalated`) : null,
  ]
    .filter(Boolean)
    .join("  ");
  return `${style.fg("▌", 96, 165, 250)} ${title}   ${tally}`;
}

function parentBlock(p, maxBins) {
  const bins = [...p.bins.values()].sort(binSort);
  const lines = [parentHeader(p)];
  for (const b of bins.slice(0, maxBins)) lines.push(binLine(b));
  if (bins.length > maxBins) {
    lines.push(dim(`        … +${bins.length - maxBins} more binaries`));
  }
  return lines;
}

function recentLines(recent, limit) {
  const out = [dim("RECENT")];
  for (const c of recent.slice(-limit).reverse()) {
    const path = paintPath(c, c.path || `(${c.comm})`);
    const tag = c.fileless
      ? " " + red("FILELESS")
      : c.scope === "tmp"
        ? " " + red("TMP")
        : c.scope === "shm"
          ? " " + red("SHM")
          : c.toRoot
            ? " " + red("→ROOT")
            : "";
    out.push(`  ${dim(hhmmss(c.wall))}  ${fit(c.pcomm, 12, "left")} ${dim("▸")} ${path}${tag}`);
  }
  return out;
}

const rule = (cols) => style.dim("─".repeat(Math.max(1, cols)));

function headerLine(snap, cols) {
  const t = snap.totals;
  const parts = [
    style.bold("runfrom"),
    `${t.execs} ${style.dim("execs")}`,
    t.ephemeral ? red(`${t.ephemeral} ephemeral`) : style.dim("0 ephemeral"),
    t.fileless ? red(`${t.fileless} fileless`) : style.dim("0 fileless"),
    t.escalated ? orange(`${t.escalated} escalated`) : style.dim("0 escalated"),
    `${snap.binCount} ${style.dim("bins")}`,
    `${snap.parentCount} ${style.dim("parents")}`,
  ];
  const left = parts.join(style.dim("  ·  "));
  const time = hhmmss();
  const pad = cols - visLen(left) - time.length;
  return pad > 1 ? left + " ".repeat(pad) + style.dim(time) : left;
}

export function renderScreen(snap, cols, rows) {
  const finite = rows !== Infinity;
  const out = [headerLine(snap, cols), rule(cols)];

  if (snap.totals.execs === 0) {
    out.push("", style.dim("  watching for execs — nothing has run yet"));
    return out.slice(0, finite ? rows : out.length).map((l) => clip(l, cols));
  }

  const maxBins = finite ? 6 : 12;
  const parents = [...snap.parents].sort(PARENT_SORTS[SORT]);
  const blocks = parents.map((p) => parentBlock(p, maxBins));

  if (!finite) {
    blocks.forEach((blk, i) => {
      if (i) out.push("");
      out.push(...blk);
    });
    return out.map((l) => clip(l, cols));
  }

  /* Live view: pack whole parent blocks into the rows left after the header,
   * reserving a line for the "+N more" marker, and append the RECENT feed
   * only when there's still comfortable room above it. */
  let avail = rows - out.length;
  const recent = recentLines(snap.recent, 6);
  const includeRecent = avail - (recent.length + 1) >= 5;
  if (includeRecent) avail -= recent.length + 1;

  const shown = [];
  let fitParents = 0;
  for (const blk of blocks) {
    const sep = shown.length ? 1 : 0;
    if (shown.length + sep + blk.length > avail - 1 && fitParents > 0) break;
    if (sep) shown.push("");
    for (const line of blk) {
      if (shown.length >= avail - 1) break;
      shown.push(line);
    }
    fitParents++;
  }
  const hidden = parents.length - fitParents;
  if (hidden > 0) shown.push(style.dim(`… +${hidden} more parents`));

  out.push(...shown);
  if (includeRecent) out.push(rule(cols), ...recent);
  return out.slice(0, rows).map((l) => clip(l, cols));
}

function size() {
  const s = (TTY && TTY.size && TTY.size()) || {};
  return {
    cols: Math.max(40, (s.cols | 0) || 100),
    rows: Math.max(10, (s.rows | 0) || 24),
  };
}

let stopped = false;
let resolveDone;
const done = new Promise((r) => (resolveDone = r));

async function shutdown(cap, restore) {
  if (stopped) return;
  stopped = true;
  if (cap) await cap.stop();
  if (restore && TTY) {
    TTY.showCursor();
    TTY.main();
  }
  resolveDone();
  if (typeof yeet !== "undefined" && yeet.exit) yeet.exit();
}

function fail(err) {
  if (TTY) {
    TTY.showCursor();
    TTY.main();
  }
  console.error(String((err && err.message) || err));
  if (typeof yeet !== "undefined" && yeet.exit) yeet.exit();
}

async function live(tracker) {
  TTY.alt();
  TTY.hideCursor();
  TTY.clear();
  if (TTY.on) TTY.on("resize", () => TTY.clear());

  const draw = () => {
    try {
      const { cols, rows } = size();
      const lines = renderScreen(tracker.snapshot(), cols, rows);
      let out = "";
      let r = 1;
      for (const line of lines) out += at(r++, 1) + ERASE + line;
      for (; r <= rows; r++) out += at(r, 1) + ERASE;
      if (TTY.beginFrame) TTY.beginFrame();
      TTY.write(out);
      if (TTY.endFrame) TTY.endFrame();
    } catch {
      /* A single bad frame shouldn't tear the dashboard down — keep the
       * last frame on screen and try again on the next tick. */
    }
  };

  let cap;
  try {
    cap = await capture((c) => tracker.add(c), (err) => console.error(String(err)));
  } catch (err) {
    return fail(err);
  }

  draw();
  const timer = setInterval(draw, INTERVAL);
  if (SECS != null) {
    setTimeout(() => {
      clearInterval(timer);
      shutdown(cap, true);
    }, SECS * 1000);
  }
  /* Keep the CLI attached so the live frames keep rendering; the interval
   * pumps while we await here. On Ctrl-C the runtime tears the isolate down
   * and the daemon detaches the probe. */
  await done;
  clearInterval(timer);
}

function once(tracker) {
  /* Piped/--once: never await a timer at top level (the runtime won't pump
   * it there), so collect via the subscription callback and let a timer
   * print the report and exit once evaluation has completed. */
  capture((c) => tracker.add(c), (err) => console.error(String(err)))
    .then((cap) => {
      setTimeout(async () => {
        try {
          const { cols } = size();
          const snap = tracker.snapshot();
          if (snap.totals.execs === 0) {
            log(style.dim(`runfrom — no execs in ${WINDOW_MS / 1000}s`));
          } else {
            for (const line of renderScreen(snap, cols, Infinity)) log(line);
          }
        } catch (err) {
          console.error(String((err && err.message) || err));
        }
        await shutdown(cap, false);
      }, WINDOW_MS);
    })
    .catch(fail);
}

if (import.meta.main) {
  const tracker = new Tracker();
  if (ONCE) {
    once(tracker);
  } else {
    live(tracker).catch(fail);
  }
  if (TTY) await done;
}
