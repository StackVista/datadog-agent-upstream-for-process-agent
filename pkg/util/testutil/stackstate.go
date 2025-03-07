package testutil

import (
	"os"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/ebpf/ebpftest"
)

func TestingStackState() bool {
	return os.Getenv("STS_TEST_RUN") != ""
}

func TestingPrebuilt() bool {
	return os.Getenv("PREBUILT_TEST_RUN") != ""
}

func SkipIfStackState(t *testing.T, reason string) {
	if TestingStackState() {
		t.Skipf("Skipping test because StackState testing is enabled: %s", reason)
	}
}

func TestingInsideDockerBuilder() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

func SkipIfInsideDockerBuilder(t *testing.T, reason string) {
	if TestingInsideDockerBuilder() {
		t.Skipf("Skipping test because we are inside a docker: %s", reason)
	}
}

func OnlyPrebuiltModeIfSelected() []ebpftest.BuildMode {
	modes := []ebpftest.BuildMode{ebpftest.Prebuilt}
	if !TestingPrebuilt() {
		modes = append(modes, ebpftest.RuntimeCompiled)
		modes = append(modes, ebpftest.CORE)
	}
	return modes
}
