#!/usr/bin/env bash

set -ex

rsync -au "$SOURCEDIR"/. $WORKDIR && chown -R root:root $WORKDIR && cd $WORKDIR
inv -e system-probe.object-files
mkdir -p ./pkg/network/nettop/ebpf && rsync -au  /opt/datadog-agent/embedded/share/system-probe/ebpf/*.o ./pkg/network/nettop/ebpf
go build -tags linux_bpf,linux ./pkg/network/nettop
# Copy the binary to the output directory so that is is available on the host machine.
cp nettop /output