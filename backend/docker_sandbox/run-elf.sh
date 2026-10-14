#!/bin/sh
set +e

if [ ! -r /input/sample.elf ] || [ ! -w /work ]; then
    echo "__SQ_SETUP_ERROR__"
    exit 125
fi

cp /input/sample.elf /work/sample.elf || exit 125
chmod 0500 /work/sample.elf || exit 125
cd /work || exit 125

timeout --signal=TERM --kill-after=2s 30s \
    strace -f -ttt -s 192 -e trace=%process,%file,%network \
    -o /tmp/sq-syscalls.log ./sample.elf \
    >/tmp/sample.stdout 2>/tmp/sample.stderr
sample_status=$?

printf '\n__SQ_EXIT_CODE__=%s\n' "$sample_status"
cat /tmp/sq-syscalls.log 2>/dev/null
exit 0
