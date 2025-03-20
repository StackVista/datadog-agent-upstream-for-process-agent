package offsetguess

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func GetNetDevQueueSkbOffset() (uint64, error) {
	formatFile := "/sys/kernel/debug/tracing/events/net/net_dev_queue/format"
	data, err := os.ReadFile(formatFile)
	if err != nil {
		return 0, fmt.Errorf("error opening %st: %w", formatFile, err)
	}

	for _, l := range strings.Split(string(data), "\n") {
		if !strings.Contains(l, "skbaddr") {
			continue
		}

		_, after, found := strings.Cut(l, "offset:")
		if !found {
			return 0, fmt.Errorf("could not find offset when parsing skbaddr in %s. Found line: %s", formatFile, l)
		}

		r, _ := regexp.Compile("[0-9]+")
		m := r.FindString(after)
		if m == "" {
			return 0, fmt.Errorf("offset for sbaddr is not numeric in %s. Found line: %s", formatFile, l)
		}

		offset, err := strconv.ParseUint(m, 0, 64)
		if err != nil {
			return 0, fmt.Errorf("offset could not be parsed in %s: %w", formatFile, err)
		}

		/* Getting the context offset can only be done on hardcoded offsets. See tracepoint_offsets.h for
		 * the full explanation.
		 * If on some platform this breaks, we should just add the offset to the possibilities to support it (also in tracepoint_offsets.h).
		 */
		if offset != 8 && offset != 16 {
			return 0, fmt.Errorf("unsupported offset %d found for net_dev_queue->skbaddr. Please contact support", offset)
		}

		return offset, nil
	}

	return 0, fmt.Errorf("could not find skbaddr in %s", formatFile)
}
