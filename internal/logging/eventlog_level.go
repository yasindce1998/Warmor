package logging

import "bytes"

type eventLevel int

const (
	levelInfo eventLevel = iota
	levelWarning
	levelError
)

// eventLogLevel maps a zerolog JSON line to an Event Viewer severity.
func eventLogLevel(line []byte) eventLevel {
	switch {
	case bytes.Contains(line, []byte(`"level":"error"`)),
		bytes.Contains(line, []byte(`"level":"fatal"`)),
		bytes.Contains(line, []byte(`"level":"panic"`)):
		return levelError
	case bytes.Contains(line, []byte(`"level":"warn"`)):
		return levelWarning
	default:
		return levelInfo
	}
}
