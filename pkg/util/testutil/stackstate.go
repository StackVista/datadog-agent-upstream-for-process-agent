package testutil

import (
	"os"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/ebpf/ebpftest"
)

func TestingStackState() bool {
	return os.Getenv("SKIP_STS_MARKED_TESTS") != ""
}

func TestingPrebuilt() bool {
	return os.Getenv("SKIP_NOT_EBPF_PREBUILT_TESTS") != ""
}

func TestingIpPackages() bool {
	return os.Getenv("SKIP_IPTABLE_TESTS") != ""
}

func SkipIfStackState(t *testing.T, reason string) {
	if TestingStackState() {
		t.Skipf("Skipping test because StackState testing is enabled: %s", reason)
	}
}

func SkipIfIpPackagesRequired(t *testing.T) {
	if TestingIpPackages() {
		t.Skipf("Skipping iptables related test")
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
