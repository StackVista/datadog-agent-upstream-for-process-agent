package testutil

import (
	"fmt"
	"os"
	"testing"
)

func TestingStackState() bool {
	return os.Getenv("STS_TEST_RUN") != ""
}

func SkipIfStackState(t *testing.T, reason string) {
	if TestingStackState() {
		t.Skip(fmt.Sprintf("Skipping test because StackState testing is enabled: %s", reason))
	}
}
