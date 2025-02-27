package testutil

import (
	"os"
	"testing"
)

func TestingStackState() bool {
	return os.Getenv("STS_TEST_RUN") != ""
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
