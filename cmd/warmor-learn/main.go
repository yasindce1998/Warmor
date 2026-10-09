package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/yasindce1998/warmor/internal/learner"
	"github.com/yasindce1998/warmor/internal/streaming"
)

var version = "dev"

// followPollInterval is how often --follow re-checks the event log for new
// lines after reaching EOF.
var followPollInterval = 250 * time.Millisecond

func main() {
	duration := flag.Duration("duration", 30*time.Minute, "Learning duration (e.g. 5m, 1h)")
	cgroups := flag.String("cgroup", "", "Comma-separated cgroup IDs to observe (empty = all)")
	output := flag.String("o", "", "Output file (default: stdout)")
	name := flag.String("name", "", "Name for the generated policy")
	eventsPath := flag.String("events", "", "Event source (required): ndjson event log written by warmor-daemon --event-sink file:<path>, a warmor-simulate event-store directory, or - for stdin")
	follow := flag.Bool("follow", false, "Keep reading events appended to the --events file until --duration elapses or Ctrl+C")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: warmor-learn [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Observe container behavior and generate a deny-all-else policy.\n\n")
		fmt.Fprintf(os.Stderr, "The learner records the security events emitted by warmor-daemon for the\n")
		fmt.Fprintf(os.Stderr, "targeted containers, then synthesizes a policy that allows only observed behavior.\n\n")
		fmt.Fprintf(os.Stderr, "Examples:\n")
		fmt.Fprintf(os.Stderr, "  warmor-learn --events /var/log/warmor/events.ndjson --cgroup 12345 -o policy.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-learn --events /var/log/warmor/events.ndjson --follow --duration 1h -o learned.yaml\n")
		fmt.Fprintf(os.Stderr, "  warmor-learn --events ./events/ -o learned.yaml\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("warmor-learn %s\n", version)
		os.Exit(0)
	}

	if *eventsPath == "" {
		fmt.Fprintf(os.Stderr, "error: --events is required (e.g. the file written by warmor-daemon --event-sink file:<path>)\n")
		os.Exit(1)
	}

	var cgroupIDs []uint64
	if *cgroups != "" {
		for s := range strings.SplitSeq(*cgroups, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			id, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid cgroup ID %q: %v\n", s, err)
				os.Exit(1)
			}
			cgroupIDs = append(cgroupIDs, id)
		}
	}

	cfg := learner.Config{
		Duration:  *duration,
		CgroupIDs: cgroupIDs,
		Name:      *name,
	}

	input, err := openEvents(*eventsPath, *follow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	defer input.Close()

	session := learner.NewSession(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\nStopping learning session...\n")
		cancel()
	}()

	fmt.Fprintf(os.Stderr, "Starting learning session (duration: %s, cgroups: %v)\n", *duration, cgroupIDs)
	fmt.Fprintf(os.Stderr, "Reading events from %s\n", *eventsPath)
	fmt.Fprintf(os.Stderr, "Press Ctrl+C to stop early and generate policy.\n\n")

	// The session ends when the duration elapses, on Ctrl+C, or (unless
	// following) once the input is exhausted.
	runCtx, stopRun := context.WithCancel(ctx)
	defer stopRun()
	feedErr := make(chan error, 1)
	go func() {
		feedErr <- feedEvents(runCtx, input, session.Recorder(), *follow)
		stopRun()
	}()

	if err := session.Run(runCtx); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	stopRun()
	// Freeze the profiles: a reader still blocked on stdin must not record
	// into them while the policy is synthesized.
	_ = session.Recorder().Close()
	select {
	case err := <-feedErr:
		if err != nil {
			fmt.Fprintf(os.Stderr, "error reading events: %v\n", err)
			os.Exit(1)
		}
	default:
	}

	stats := session.Stats()
	fmt.Fprintf(os.Stderr, "\nLearning complete: %s\n", stats)

	if stats.Containers == 0 {
		fmt.Fprintf(os.Stderr, "error: no events recorded from %s", *eventsPath)
		if len(cgroupIDs) > 0 {
			fmt.Fprintf(os.Stderr, " for cgroups %v", cgroupIDs)
		}
		fmt.Fprintf(os.Stderr, "; refusing to write an empty deny-all policy\n")
		os.Exit(1)
	}

	data, err := session.MarshalPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", *output, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Policy written to %s\n", *output)
	} else {
		os.Stdout.Write(data)
	}
}

// openEvents opens the event source named by path: "-" for stdin, a
// directory of warmor-simulate event-store files (events-*.ndjson, read in
// name order), or a single ndjson file.
func openEvents(path string, follow bool) (io.ReadCloser, error) {
	if path == "-" {
		if follow {
			return nil, errors.New("--follow requires an event log file, not stdin")
		}
		return io.NopCloser(os.Stdin), nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("open events: %w", err)
	}
	if !info.IsDir() {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open events: %w", err)
		}
		return f, nil
	}

	if follow {
		return nil, errors.New("--follow requires an event log file, not a directory")
	}
	files, err := filepath.Glob(filepath.Join(path, "events-*.ndjson"))
	if err != nil {
		return nil, fmt.Errorf("glob event files: %w", err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no events-*.ndjson files in %s", path)
	}
	sort.Strings(files)
	return &multiFileReader{paths: files}, nil
}

// multiFileReader reads a list of files back to back, opening each lazily.
// A newline is inserted after a file that does not end in one so its last
// event cannot run into the next file's first.
type multiFileReader struct {
	paths []string
	cur   *os.File
	last  byte
}

func (m *multiFileReader) Read(p []byte) (int, error) {
	for {
		if m.cur == nil {
			if len(m.paths) == 0 {
				return 0, io.EOF
			}
			f, err := os.Open(m.paths[0])
			if err != nil {
				return 0, err
			}
			m.cur, m.paths = f, m.paths[1:]
		}
		n, err := m.cur.Read(p)
		if n > 0 {
			m.last = p[n-1]
		}
		if err == io.EOF {
			_ = m.cur.Close()
			m.cur = nil
			if n > 0 {
				return n, nil
			}
			if m.last != '\n' && m.last != 0 && len(p) > 0 {
				p[0], m.last = '\n', '\n'
				return 1, nil
			}
			continue
		}
		return n, err
	}
}

func (m *multiFileReader) Close() error {
	if m.cur != nil {
		return m.cur.Close()
	}
	return nil
}

// feedEvents decodes newline-delimited SecurityEvents from r into sink until
// EOF. With follow set, EOF means "no new events yet": reading resumes after
// followPollInterval until ctx is done, and a trailing partial line is held
// back until its newline arrives. Malformed lines are skipped with a warning.
func feedEvents(ctx context.Context, r io.Reader, sink streaming.Sink, follow bool) error {
	br := bufio.NewReader(r)
	var line []byte
	lineNum := 0
	for ctx.Err() == nil {
		chunk, err := br.ReadBytes('\n')
		line = append(line, chunk...)
		if err != nil && err != io.EOF {
			return err
		}
		complete := err == nil || (!follow && len(line) > 0)
		if complete {
			lineNum++
			if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
				var ev streaming.SecurityEvent
				if jerr := json.Unmarshal(trimmed, &ev); jerr != nil {
					fmt.Fprintf(os.Stderr, "warning: skipping malformed event on line %d: %v\n", lineNum, jerr)
				} else if werr := sink.Write(ctx, &ev); werr != nil {
					return werr
				}
			}
			line = line[:0]
		}
		if err == io.EOF {
			if !follow {
				return nil
			}
			select {
			case <-ctx.Done():
			case <-time.After(followPollInterval):
			}
		}
	}
	return nil
}
