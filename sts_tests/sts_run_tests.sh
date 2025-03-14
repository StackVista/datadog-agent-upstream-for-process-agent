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

# Selected test suites for testing
echo "Running suites"

# Run Config tests
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/config/.

# Run protocols tests
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/protocols/.

# Run Process Monitor tests
# These tests need to run without concurrency
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/process/monitor/.

# Run the tests for MongoDB
# To also run the TLS test, provide a MONGODB_URI for a TLS-enabled instance, e.g.:
# export MONGODB_URI="mongodb+srv://user:pass@my-cluster.mongodb.com/?retryWrites=true&w=majority"
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/.*Mongo.*"
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/TestProtocolClassification/without_nat/mongo$"

# Run the tests for AMQP
# There is also a TLS test available, but it needs manual intervention as of now.
# See TestAMQPOverTLSStats in tracker_usm_linux_test.go
invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/usm/. --test-run-name="^TestUSMSuite/prebuilt/TestAMQPStats$"
 
# Run the tests for shared libraries (skipped for now)
# invoke test --build-include=linux_bpf,test --cpus=1 --targets=./pkg/network/usm/sharedlibraries/.

# Run HTTP suite
invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --test-run-name="^TestHTTP/prebuilt/.*" --timeout=400

# Run USM test suite (Quite slow could take up to 5 minutes)
# - `TestUSMSuite/prebuilt/TestIgnoreTLSClassificationIfApplicationProtocolWasDetected/POSTGRES` could be flaky
# - `TestUSMSuite/prebuilt/TestProtocolClassification/with_dnat/http2/http2_traffic_using_gRPC_-_irrelevant_literal_headers` fails
invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/tests/. --timeout=400

# Run tracer suite (Quite slow could take up to 5 minutes)
invoke test --build-include=linux_bpf,test --targets=./pkg/network/tracer/. --timeout=400

# Run full USM suite
invoke test --build-include=linux_bpf,test --targets=./pkg/network/usm/. --timeout=1000

# Run Network suite
invoke test --build-include=linux_bpf,test --targets=./pkg/network/. --timeout=1000