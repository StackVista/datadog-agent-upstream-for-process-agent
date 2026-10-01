# Temporary Viper compatibility backport

Source: https://github.com/DataDog/viper
Base: 23b76a0698669ac4e62cca8dc70a666c1f877b99 (v1.14.0).
All upstream tracked source, tests and LICENSE are retained. The only
source change selects maintained go.yaml.in/yaml/v2; module metadata
selects v2.4.4 and Go 1.15. HCL, filesystem and mapstructure APIs remain.

Temporary ownership/removal tracking: https://github.com/StackVista/stackstate/issues/717
The logical module identity remains github.com/DataDog/viper. Consumers
must explicitly replace it with this repository's third_party/viper module;
replacements in dependency manifests do not propagate.
