package store

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseInterval accepts "90", "90m", "6h" or "1d" and returns minutes and
// the display unit.
func ParseInterval(s string) (int, string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, "", fmt.Errorf("empty interval")
	}
	mult, unit := 1, "minutes"
	switch {
	case strings.HasSuffix(s, "d"):
		mult, unit, s = 1440, "days", strings.TrimSuffix(s, "d")
	case strings.HasSuffix(s, "h"):
		mult, unit, s = 60, "hours", strings.TrimSuffix(s, "h")
	case strings.HasSuffix(s, "m"):
		s = strings.TrimSuffix(s, "m")
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 0, "", fmt.Errorf("invalid interval %q (use e.g. 30m, 6h, 1d)", s)
	}
	return n * mult, unit, nil
}

func parseBool(name, v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%s: expected true/false, got %q", name, v)
}

// ApplyEnv overrides settings from environment variables (for containers).
// Only variables that are set change anything; it reports which were used.
//
//	SADNS_SCHEDULE_ENABLED   true/false
//	SADNS_SCHEDULE_INTERVAL  30m, 6h, 1d (minimum 5m)
//	SADNS_SCHEDULE_MODE      quick/full
//	SADNS_SCHEDULE_LOW_DATA  true/false
//	SADNS_HISTORY_RETAIN     number of unpinned scans to keep
func ApplyEnv(set *Settings, getenv func(string) string) ([]string, error) {
	var used []string
	if v := getenv("SADNS_SCHEDULE_ENABLED"); v != "" {
		b, err := parseBool("SADNS_SCHEDULE_ENABLED", v)
		if err != nil {
			return nil, err
		}
		set.Schedule.Enabled = b
		used = append(used, "SADNS_SCHEDULE_ENABLED")
	}
	if v := getenv("SADNS_SCHEDULE_INTERVAL"); v != "" {
		n, unit, err := ParseInterval(v)
		if err != nil {
			return nil, fmt.Errorf("SADNS_SCHEDULE_INTERVAL: %w", err)
		}
		set.Schedule.IntervalMinutes, set.Schedule.Unit = n, unit
		used = append(used, "SADNS_SCHEDULE_INTERVAL")
	}
	if v := getenv("SADNS_SCHEDULE_MODE"); v != "" {
		set.Schedule.Mode = strings.ToLower(v)
		used = append(used, "SADNS_SCHEDULE_MODE")
	}
	if v := getenv("SADNS_SCHEDULE_LOW_DATA"); v != "" {
		b, err := parseBool("SADNS_SCHEDULE_LOW_DATA", v)
		if err != nil {
			return nil, err
		}
		set.Schedule.LowData = b
		used = append(used, "SADNS_SCHEDULE_LOW_DATA")
	}
	if v := getenv("SADNS_HISTORY_RETAIN"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, fmt.Errorf("SADNS_HISTORY_RETAIN: %w", err)
		}
		set.Retain = n
		used = append(used, "SADNS_HISTORY_RETAIN")
	}
	if len(used) > 0 {
		if err := set.Validate(); err != nil {
			return nil, err
		}
	}
	return used, nil
}
