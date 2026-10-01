---
title: Datadog Agent Upstream for Process Agent
type: repo
sources: [StackVista/datadog-agent-upstream-for-process-agent, StackVista/stackstate-process-agent, StackState.md, go.mod, go.work, tasks]
last_updated: 2026-10-01
---

# Datadog Agent Upstream for Process Agent

[Source repository](https://github.com/StackVista/datadog-agent-upstream-for-process-agent) is the maintained Datadog fork consumed by [stackstate-process-agent](stackstate-process-agent.md). It supplies process collection, container metadata, configuration, logging and native network/runtime-security dependencies. It retains upstream agent commands and supported platform implementations beyond the downstream product's linked packages.

## Modules and downstream consumption

The repository retains DataDog Go module identities. The root and nested modules form a workspace through `go.work`; each module has independent requirements and sums. The consumer maps those identities to this fork through replacement directives. Root-only revision changes do not update nested module replacements. Inspect the consuming manifest and effective target graph before deciding what reaches a product binary.

## Configuration contracts

The configuration model wraps Viper with synchronized access and source precedence. Setup, node-tree, secrets and scrubbing modules implement configuration boundaries. Preserve format support, environment handling and scalar values. YAML custom-node methods in process Java metadata, service discovery and security policies must use the same node identity as their decoder. Windows registry configuration converts YAML through JSON before schema validation; direct raw YAML decoding is not equivalent.

## Native builds and tests

`StackState.md` describes qualification through the consumer and its existing prebuild/test scripts. Native network and runtime-security builds require generated Go/eBPF assets and appropriate builders. Package listing does not qualify native compilation. Run focused module tests and fixture suites, then consumer tests with its actual build tags and supported architectures. Windows cross-compilation checks source compatibility without proving Windows execution.

## Maintenance and delivery

Follow the maintained product branch and upstream-update strategy in `StackState.md`. Inherited upstream release workflows do not establish the fork's delivery pipeline. The consumer owns product packaging, image checks and adoption. Keep module pins coherent, retain license attribution and normal checksum/provenance gates, and distinguish owned imports, test dependencies, generation tools and linked production code.
