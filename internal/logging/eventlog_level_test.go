package logging

import "testing"

func TestEventLogLevel(t *testing.T) {
	cases := map[string]eventLevel{
		`{"level":"error","message":"x"}`: levelError,
		`{"level":"fatal","message":"x"}`: levelError,
		`{"level":"warn","message":"x"}`:  levelWarning,
		`{"level":"info","message":"x"}`:  levelInfo,
		`not json`:                        levelInfo,
	}
	for line, want := range cases {
		if got := eventLogLevel([]byte(line)); got != want {
			t.Errorf("eventLogLevel(%s) = %d, want %d", line, got, want)
		}
	}
}
