#!/usr/bin/env bash
# runfrom demo — give the panel something to judge. A single long-lived shell
# loops a spread of execs: ordinary ones from /usr/bin, a binary dropped in
# /tmp and one in /dev/shm, a genuinely fileless exec (unlink then run via the
# open fd), and a setuid binary. They all share the loop's PID as their
# parent, so they stack under one block whose flag counts climb.
#
#   cd examples/runfrom && ./demo.sh
#
# The generator is killed when you Ctrl-C out. Pass extra flags through,
# e.g. ./demo.sh --sort execs
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"

bold=$'\e[1m'; dim=$'\e[2m'; red=$'\e[31m'; grn=$'\e[32m'; rst=$'\e[0m'

TMPBIN=/tmp/runfrom_demo
SHMBIN=/dev/shm/runfrom_demo
SRC=/bin/true
# A genuinely setuid-root binary; exec'ing it is the privilege signal. mount
# with no args just lists filesystems, so it's harmless to run on a loop.
SETUID="$(command -v mount || echo /bin/mount)"

# A fileless exec: copy a binary, hold it open on an fd, unlink it so it has
# no name on disk, then exec it through /proc/self/fd — the kernel sees an
# inode with link count 0, which is exactly the memfd/dropper signature.
fileless() {
  local f=/tmp/runfrom_fl.$$
  cp "$SRC" "$f" 2>/dev/null || return
  exec 7<"$f"
  rm -f "$f"
  /proc/self/fd/7 2>/dev/null || true
  exec 7<&-
}

gen() {
  cp "$SRC" "$TMPBIN" 2>/dev/null
  cp "$SRC" "$SHMBIN" 2>/dev/null
  while :; do
    /bin/ls >/dev/null 2>&1
    /usr/bin/id >/dev/null 2>&1
    "$TMPBIN" 2>/dev/null              # exec from /tmp        -> TMP
    "$SHMBIN" 2>/dev/null              # exec from /dev/shm    -> SHM
    fileless                           # unlinked, run via fd  -> FILELESS
    "$SETUID" >/dev/null 2>&1          # setuid-root binary    -> suid / ->ROOT
    sleep 1.5
  done
}

gen &
GEN=$!
cleanup() {
  kill "$GEN" 2>/dev/null
  pkill -P "$GEN" 2>/dev/null
  rm -f "$TMPBIN" "$SHMBIN" /tmp/runfrom_fl.* 2>/dev/null
}
trap cleanup EXIT INT TERM

cat <<EOF

${bold}runfrom${rst} — where is this code running from?

One shell is looping execs: plain ${dim}/usr/bin${rst} tools, a binary dropped in
${red}/tmp${rst} and one in ${red}/dev/shm${rst}, a ${red}fileless${rst} exec (unlinked, run via an open
fd), and a ${bold}setuid${rst} binary. Watch the loop's exec counts climb and the
${red}TMP${rst} / ${red}SHM${rst} / ${red}FILELESS${rst} flags trip — and run ${bold}./demo.sh${rst} as a non-root
user to see the setuid jump flagged ${red}→ROOT${rst}. ${dim}Ctrl-C stops it all.${rst}

EOF

cd "$HERE"
exec yeet run main.js "$@"
