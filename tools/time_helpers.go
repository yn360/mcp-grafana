package tools

import (
	"fmt"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend/gtime"
)

// timeParamHint returns the canonical phrase appended to every time-parameter
// jsonschema description. It warns callers that naive timestamps (no timezone
// offset) are interpreted as UTC by the server, and suggests the two safe
// forms: an RFC3339 timestamp with an explicit offset (e.g. '-05:00') or the
// relative 'now-Xh' syntax accepted by gtime.
//
// The returned string is copy-pasted into each jsonschema tag rather than
// interpolated, because Go struct tags must be string literals. Keep this
// function in sync with those tags; update both together. Some tags append an
// extra clause tailored to the tool (e.g. 'to render in a different timezone'
// for rendering tools), but all of them must contain this canonical phrase
// verbatim — TestTimeParamHint enforces that.
func timeParamHint() string {
	return "Timestamps without a timezone offset are interpreted as UTC; include an offset like '-05:00'"
}

// parseStartTime parses start time strings in various formats.
// Supports: "now", "now-Xs/m/h/d/w", RFC3339, ISO dates, and Unix timestamps.
func parseStartTime(timeStr string) (time.Time, error) {
	if timeStr == "" {
		return time.Time{}, nil
	}

	tr := gtime.TimeRange{
		From: timeStr,
		Now:  time.Now(),
	}
	t, err := tr.ParseFrom()
	if err != nil {
		return time.Time{}, fmt.Errorf("%w. %s", err, timeParamHint())
	}
	return t, nil
}

// parseEndTime parses end time strings in various formats.
// For end times, date-only strings resolve to end of day rather than start.
func parseEndTime(timeStr string) (time.Time, error) {
	if timeStr == "" {
		return time.Time{}, nil
	}

	tr := gtime.TimeRange{
		To:  timeStr,
		Now: time.Now(),
	}
	t, err := tr.ParseTo()
	if err != nil {
		return time.Time{}, fmt.Errorf("%w. %s", err, timeParamHint())
	}
	return t, nil
}
