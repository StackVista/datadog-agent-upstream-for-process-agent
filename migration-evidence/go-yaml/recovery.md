# YAML dependency candidate recovery

Tracking: https://github.com/StackVista/stackstate/issues/717

The runner lost the unpushed dependency edits, local Viper commit and temporary logs.
Reconstructed from the same session's recorded source and validation evidence;
PR853 head 8c5f63ba153fa0598fce6d04ea1b5d3636cabc9d was independently verified.

Owner upgrades: Kubernetes api/apimachinery/client-go/component-base v0.32.13,
kube-openapi v0.0.0-20250627150254-e9823e99808e, gnostic-models v0.7.0,
swag and its submodules v0.25.1. Matching owners in E2E and OTel modules
are aligned. Swag requires Go 1.24, reflected in those module minima;
root Go remains 1.25.7. Other inherited Kubernetes modules stay at their
existing requirements; focused compilation is not full cluster qualification.

The narrow Viper patch retains HCL, filesystem and mapstructure APIs on
DataDog/viper v1.14.0 (base 23b76a0698669ac4e62cca8dc70a666c1f877b99).
Reconstructed signed commit: 5fe269f5aadefd35b72db8318cea32e3ad6aa013.
Fresh workspace tests pass for Datadog HCL value and Viper HCL/YAML
read/write, merge and unmarshal. The earlier session recorded the same
pflag StringSlice nil/empty failure on original and backported source.

Viper publication is blocked: DataDog/viper has no push permission;
StackVista/viper returns 404 via gh and the Mission Control fallback;
creating a StackVista fork returns HTTP403 via both. No permissions changed.
The signed format-patch is preserved here for the controller to import into
an accessible owning fork. It is not a resolvable published module revision.
Do not insert a fabricated pseudo-version or a local path into product pins.

Owned direct YAML migration from the prior signed head is retained.
Residual Viper old v2 remains active until the owning backport is published
and adopted. Other entrypoints can still link old v3 via Collector confmap;
ghodss remains generation tooling via grpc-gateway. Historical sums alone
are not a runtime finding. Full native generation, product architectures,
image gates and downstream adoption remain controller/consumer work.

The complete wiki page is included for controller publication in Mission
Control with its index and repos.yaml wiki status update.

Fresh recovered-checkpoint validation (Go 1.26.8 linux/amd64): six focused
parser/config suites pass (Java scalar regression, jsonquery, agent import,
autodiscovery integration/configresolver, SNMP checkconfig). Windows registry
cross-compiles with no test files; no Windows execution. Root effective
module identities have no duplicates and no YAML replacement directives.
Process/tracer package graph has 2006 packages; only Viper imports old v2.
At this early checkpoint the larger builds, nested suites and checksum/tidy
rechecks are running; later results must be read separately, not inferred.
