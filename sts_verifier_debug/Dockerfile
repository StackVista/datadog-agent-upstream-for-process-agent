# ---------------------------
# BUILDER STAGE
# ---------------------------
FROM quay.io/stackstate/datadog_build_system-probe_x64:0d87e00f AS builder

WORKDIR /source

COPY . /source

# This puts the .o files in `/opt/datadog-agent/embedded/share/system-probe/ebpf`
RUN inv -e system-probe.object-files

# This moves the .o files into the right folder so that we can use go embed
RUN mkdir -p ./pkg/network/nettop/ebpf && \
    cp -r /opt/datadog-agent/embedded/share/system-probe/ebpf/*.o ./pkg/network/nettop/ebpf

# This puts the binary in in the current directory so `/source`
# The binary embeds the .o files thanks to the `go:embed` directive
RUN go build -tags linux_bpf,linux ./pkg/network/nettop 

# ---------------------------
# EXPORT STAGE
# ---------------------------
FROM scratch AS export-stage

COPY --from=builder /source/nettop nettop

# ---------------------------
# FINAL STAGE
# ---------------------------
FROM debian:bookworm-slim

COPY --from=builder /source/sts_verifier_debug/entrypoint.sh /entrypoint.sh
COPY --from=builder /source/nettop /usr/bin/nettop

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

# By default we want to run our binary
CMD ["nettop"]