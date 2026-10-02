# Remaining owning parser boundaries

Tracking: https://github.com/StackVista/stackstate/issues/717

Base candidate b06402db3fadaf13c3d052ca96b14671dee22521 is retained.
Do not repeat its process-agent/tracer, original nine/46 consumer or Viper
qualification. This follow-up owns complete published Go module distributions
of goflow2 v1.3.3, Collector confmap v1.21.0 and grpc-gateway v1.16.0.
The distribution manifest records immutable sums, zip SHA256, Git refs and
revisions, all files/modes, and exact approved patched-file checksums. Module
zip distributions are the immutable Go build sources; no asset-filtered git
archive or custom file selection is used. Licenses, generated files, ignored
assets included in official distributions, and upstream tests are retained.

Boundaries:
- comp/netflow/goflowlib and server import goflow2/utils. LoadMapping decodes
  producer mappings with matching maintained v2.4.4; original API generation
  and protobuf messages remain. Runtime path, not merely sum metadata.
- cmd/otel-agent/config creates a confmap resolver. Its provider and internal
  mapstructure encoder use maintained v3.0.5, including custom Node methods;
  confmaptest and upstream tests use the same node identity. Collector APIs
  stay at v1.21.0; no modern Collector wholesale update.
- tasks/install_tasks.py installs grpc-gateway's generator and API tools.go
  records it under tools. Its descriptor's YAML service-config path still
  calls YAMLToJSON then jsonpb with AllowUnknownFields. Only this wrapper
  import moves to sigs.k8s.io/yaml v1.6.0. Generator is executable even though
  tools.go itself is a dependency-tracking file. Swagger and grpc generation
  contracts remain covered by preserved upstream fixture suites.

Root and existing affected modules explicitly select local owning candidates;
workspace includes them. Logical upstream module paths remain unchanged.
Consumers must explicitly select remote owning module candidates because
replacements do not propagate. No downstream process-agent pins are changed.

Run check_owner_distributions.py and test_owner_distributions.py. Negative
controls prove source omission, license alteration, mode change and parser
reintroduction fail. No active workflows, pipeline permission/gate changes,
new tickets, releases, deployment or infrastructure changes.

Existing boundaries remain: generated runtime.Tracer/RuntimeSecurity assets,
Windows native execution and full Viper baseline pflag nil/empty failure.
This change does not claim full inherited Datadog runtime/image qualification.
