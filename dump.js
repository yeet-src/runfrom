/* runfrom dump — every exec as newline-delimited JSON, one object per
 * execve, straight from the kernel probe with no aggregation. Feed it to
 * jq, a log pipeline, or a file.
 *
 *   yeet run examples/runfrom/dump.js
 *   yeet run examples/runfrom/dump.js | jq -c 'select(.ephemeral or .fileless)'
 *   yeet run examples/runfrom/dump.js -- --secs 10 > execs.ndjson
 *   yeet run examples/runfrom/dump.js -- --count 50 | jq -r '[.comm,.path,.uid,.euid]|@tsv'
 */

import { capture } from "./data.js";

const args = (typeof yeet !== "undefined" && yeet.args) || {};
const SECS = args.secs != null ? Number(args.secs) : null;
const COUNT = args.count != null ? Math.max(1, Number(args.count) | 0) : null;

let n = 0;
let stopped = false;
let cap = null;

async function shutdown() {
  if (stopped) return;
  stopped = true;
  if (cap) {
    try {
      await cap.stop();
    } catch {}
  }
  if (typeof yeet !== "undefined" && yeet.exit) yeet.exit();
}

try {
  cap = await capture(
    (c) => {
      if (stopped) return;
      console.log(JSON.stringify(c));
      if (COUNT && ++n >= COUNT) shutdown();
    },
    (err) => console.error(String(err)),
  );
} catch (err) {
  console.error(String((err && err.message) || err));
  if (typeof yeet !== "undefined" && yeet.exit) yeet.exit();
}

if (cap && SECS != null) setTimeout(shutdown, SECS * 1000);
