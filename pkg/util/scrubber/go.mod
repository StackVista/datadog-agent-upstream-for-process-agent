module github.com/DataDog/datadog-agent/pkg/util/scrubber

go 1.22.0

require (
	github.com/DataDog/datadog-agent/pkg/version v0.62.2
	github.com/stretchr/testify v1.12.1
	go.yaml.in/yaml/v3 v3.0.5
)

replace github.com/DataDog/datadog-agent/pkg/version => ../../version
