//go:build unit

package tools

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTimeParamHint verifies the canonical hint text and confirms that the
// time-range params we care about keep the hint in their jsonschema
// descriptions. If either the hint or a tag drifts out of sync this test
// fails, which is the whole point — the helper documents the expected wording
// for the tags.
func TestTimeParamHint(t *testing.T) {
	hint := timeParamHint()
	require.NotEmpty(t, hint)
	assert.Contains(t, hint, "UTC")
	assert.Contains(t, hint, "-05:00")

	substr := strings.TrimSpace(hint)

	type sample struct {
		value  interface{}
		fields []string
	}

	samples := []sample{
		{QueryLokiLogsParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{QueryLokiStatsParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{QueryLokiPatternsParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{ListLokiLabelNamesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{ListLokiLabelValuesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{QueryPrometheusParams{}, []string{"StartTime", "EndTime"}},
		{ListPrometheusLabelNamesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{ListPrometheusLabelValuesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{QueryPrometheusHistogramParams{}, []string{"StartTime", "EndTime"}},
		{ClickHouseQueryParams{}, []string{"Start", "End"}},
		{CloudWatchQueryParams{}, []string{"Start", "End"}},
		{QueryElasticsearchParams{}, []string{"StartTime", "EndTime"}},
		{SearchLogsParams{}, []string{"Start", "End"}},
		{FindSlowRequestsParams{}, []string{"Start", "End"}},
		{FindErrorPatternLogsParams{}, []string{"Start", "End"}},
		{ListPyroscopeLabelNamesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{ListPyroscopeLabelValuesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{ListPyroscopeProfileTypesParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{QueryPyroscopeParams{}, []string{"StartRFC3339", "EndRFC3339"}},
		{RunPanelQueryParams{}, []string{"Start", "End"}},
		{GetAssertionsParams{}, []string{"StartTime", "EndTime"}},
		{AddActivityToIncidentParams{}, []string{"EventTime"}},
		{TimeRange{}, []string{"From", "To"}},
		{RenderTimeRange{}, []string{"From", "To"}},
	}

	for _, s := range samples {
		ty := reflect.TypeOf(s.value)
		for _, name := range s.fields {
			f, ok := ty.FieldByName(name)
			require.True(t, ok, "field %s.%s not found", ty.Name(), name)
			tag := f.Tag.Get("jsonschema")
			assert.Contains(t, tag, substr, "%s.%s jsonschema tag missing time hint", ty.Name(), name)
		}
	}
}

func TestParseStartTime(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		checkFunc   func(t *testing.T, result time.Time)
	}{
		{
			name:  "empty string returns zero time",
			input: "",
			checkFunc: func(t *testing.T, result time.Time) {
				assert.True(t, result.IsZero())
			},
		},
		{
			name:  "now returns current time",
			input: "now",
			checkFunc: func(t *testing.T, result time.Time) {
				assert.WithinDuration(t, time.Now(), result, 5*time.Second)
			},
		},
		{
			name:  "now-1h returns time 1 hour ago",
			input: "now-1h",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Now().Add(-1 * time.Hour)
				assert.WithinDuration(t, expected, result, 5*time.Second)
			},
		},
		{
			name:  "now-30m returns time 30 minutes ago",
			input: "now-30m",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Now().Add(-30 * time.Minute)
				assert.WithinDuration(t, expected, result, 5*time.Second)
			},
		},
		{
			name:  "now-6h returns time 6 hours ago",
			input: "now-6h",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Now().Add(-6 * time.Hour)
				assert.WithinDuration(t, expected, result, 5*time.Second)
			},
		},
		{
			name:  "now-1d returns time 1 day ago",
			input: "now-1d",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Now().Add(-24 * time.Hour)
				assert.WithinDuration(t, expected, result, 5*time.Second)
			},
		},
		{
			name:  "RFC3339 format",
			input: "2024-01-15T10:00:00Z",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseStartTime(tt.input)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}

func TestParseEndTime(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		checkFunc   func(t *testing.T, result time.Time)
	}{
		{
			name:  "empty string returns zero time",
			input: "",
			checkFunc: func(t *testing.T, result time.Time) {
				assert.True(t, result.IsZero())
			},
		},
		{
			name:  "now returns current time",
			input: "now",
			checkFunc: func(t *testing.T, result time.Time) {
				assert.WithinDuration(t, time.Now(), result, 5*time.Second)
			},
		},
		{
			name:  "now-1h returns time 1 hour ago",
			input: "now-1h",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Now().Add(-1 * time.Hour)
				assert.WithinDuration(t, expected, result, 5*time.Second)
			},
		},
		{
			name:  "RFC3339 format",
			input: "2024-01-15T10:00:00Z",
			checkFunc: func(t *testing.T, result time.Time) {
				expected := time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseEndTime(tt.input)
			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.checkFunc != nil {
				tt.checkFunc(t, result)
			}
		})
	}
}
