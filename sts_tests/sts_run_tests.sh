#!/usr/bin/env bash

set -ex

if ! stat /.dockerenv >/dev/null 2>&1; then
  echo "error: this script should run inside our docker image" >&2
  exit 1
fi

if ! type "rsync" > /dev/null; then
  apt install rsync -y --no-install-recommends
fi

if ! test -f /usr/local/bin/docker-compose; then
   curl -SL https://github.com/docker/compose/releases/download/v2.23.3/docker-compose-linux-x86_64 -o /usr/local/bin/docker-compose
   chmod +x /usr/local/bin/docker-compose
fi

# We install these dependencies but we don't use them by default.
# To skip tests releated to iptables and conntrack use the env variable export `SKIP_IPTABLE_TESTS=true`.
# If you don't skip them please pay attention since these tests could alter the network state of your local machine.
export SKIP_IPTABLE_TESTS=true
apt install iptables conntrack iproute2 -y --no-install-recommends

# This command assumes the datadog agent to be mounted at /source-datadog-agent. To avoid outputting to that directory,
# we make a clone before running any commands
mkdir -p $WORKDIR
rsync -au "$SOURCEDIR"/. $WORKDIR
chown -R root:root $WORKDIR
cd $WORKDIR

# Adding a faux tag to make the build pass on the rpo with no tags
git config user.email "you@example.com"
git config user.name "Your Name"
git tag -a 7.0.0 -m 7.0.0 || true

mount -t debugfs none /sys/kernel/debug/ || true

invoke install-tools

invoke system-probe.build

export DD_SYSTEM_PROBE_BPF_DIR=$WORKDIR/pkg/ebpf/bytecode/build/

export SKIP_STS_MARKED_TESTS=true
# Run tests only in prebuilt mode
export SKIP_NOT_EBPF_PREBUILT_TESTS=true

# Quickly check if there is a verifier failure
# invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/TestVerifierComplexity.*"

# See the number of instructions for each program
# invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --test-run-name="^TestHTTP/prebuilt/TestHTTPMonitorInstructionCounts"

# With 'full-suite' argument we execute all tests, but it could be slow (6/7 min)
# By default we only run some of them
if [[ "$1" == "full-suite" ]]; then
    echo "--------------------- Run full test suite---------------------"
    invoke test --build-include=linux_bpf,test --targets=./pkg/network/. --timeout=500
else
    echo "--------------------- Run simple test suite---------------------"
    # Run tests on postgres protocol enrichment
    invoke test --build-include=linux_bpf,test --targets=./pkg/network/protocols/postgres/.
    invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --test-run-name="^TestPostgres.*"
    # Run tests on protocol enrichment (no postgres) + protocol classification
    invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/.*" --timeout=300
    # Run tests on HTTP protocol enrichment
    invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --test-run-name="^TestHTTP/prebuilt/.*"
fi
