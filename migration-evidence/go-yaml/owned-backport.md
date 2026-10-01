# Owned Viper and patched Swag candidate

Tracking: https://github.com/StackVista/stackstate/issues/717

Supersedes the inaccessible-fork limitation in recovery.md. third_party/viper
owns upstream base 23b76a0698669ac4e62cca8dc70a666c1f877b99. All tracked
source/tests/license are retained; only viper.go/go.mod/go.sum differ,
selecting maintained YAML v2.4.4 and Go1.15. Explicit replacements select
this source for root/affected modules; go.work includes it. The original
logical module identity remains github.com/DataDog/viper. Consumers MUST
provide their own replacement to the published third_party/viper candidate.
Upstream removal remains tracked under the shared issue.

Swag facade remains v0.25.1; jsonutils/yamlutils and required support
conv/typeutils/pools select patched v0.27.1. Primary advisories:
https://github.com/go-openapi/swag/security/advisories/GHSA-xh24-9qpg-8w28
https://github.com/go-openapi/swag/security/advisories/GHSA-hwp8-w8pv-xq8f
Both affect <=0.27.0. Root Go1.25.7 is retained; E2E and two affected OTel
modules require Go1.25.0. No fabricated versions or parser-path replacements.

Fresh upstream jsonutils/yamlutils complete suites pass at upstream
c8a41f7226ee09d8f74ac3e9375d071041836b7c, including JSON deep read/write
and YAML nesting/alias-expansion rejection and ordered-map contracts.
Datadog config model/structure and focused upstream Viper HCL/YAML
read/write, merge/unmarshal pass. Viper full tests retain the baseline
pflag StringSlice nil-versus-empty failure; do not suppress it.

Preserved upstream .github workflows are nested source archives and not
active repository workflows. Zizmor ran and reported inherited settings
including unpinned actions and credential persistence; no active pipeline
permissions or gates were changed. Product CI/native generation, platform
execution and image adoption remain independently qualified.

Qualified process-agent/tracer package graph with consumer tags kubelet,
kubeapiserver, linux, cri, containerd, linux_bpf: 2006 packages, no imports
of old v2/v3 or ghodss. Root module identities have no duplicates and no
YAML replacements. Six focused parser/config fixture suites pass. At this
checkpoint larger builds, Windows and nested suites remain running.
