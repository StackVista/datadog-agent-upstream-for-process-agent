package utils_test

import (
	"strings"
	"testing"

	"github.com/netsampler/goflow2/utils"
)

func TestMaintainedMappingContract(t *testing.T) {
	c, err := utils.LoadMapping(strings.NewReader(`sflow:
  mapping:
    - layer: 2
      offset: 8
      length: 16
      destination: "off"
      endianness: little
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.SFlow.Mapping) != 1 {
		t.Fatal(c)
	}
	m := c.SFlow.Mapping[0]
	if m.Layer != 2 || m.Offset != 8 || m.Length != 16 || m.Destination != "off" {
		t.Fatal(m)
	}
	if _, err := utils.LoadMapping(strings.NewReader("sflow: [")); err == nil {
		t.Fatal("malformed mapping accepted")
	}
}
