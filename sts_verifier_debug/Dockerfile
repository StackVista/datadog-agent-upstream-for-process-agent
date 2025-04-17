# ---------------------------
# STAGE 1
# ---------------------------
FROM quay.io/stackstate/datadog_build_system-probe_x64:0d87e00f AS builder

WORKDIR /source

COPY . /source

# This puts the .o files in `/opt/datadog-agent/embedded/share/system-probe/ebpf`
RUN inv -e system-probe.object-files

# This puts the binary in in the current directory so `/source`
RUN go build -tags linux_bpf,linux ./pkg/network/nettop 

# ---------------------------
# STAGE 2
# ---------------------------
FROM debian:bookworm-slim

COPY --from=builder /opt/datadog-agent/embedded/share/system-probe/ebpf /ebpf_artifacts
COPY --from=builder /source/sts_verifier_debug/entrypoint.sh /entrypoint.sh
COPY --from=builder /source/nettop /usr/bin/nettop

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# By default we want to run our binary
CMD ["nettop"]