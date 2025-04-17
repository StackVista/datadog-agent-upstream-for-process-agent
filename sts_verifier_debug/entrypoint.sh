#!/bin/sh
echo "Mounting debugfs for our ebpf progs..."
mount -t debugfs none /sys/kernel/debug/

# It executes the command of the user or the default `CMD`
exec "$@"