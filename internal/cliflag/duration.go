package cliflag

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const day = 24 * time.Hour

// ParseDuration is time.ParseDuration plus a leading day component: "7d",
// "1.5d" and "1d12h" are accepted alongside every Go duration ("90m",
// "168h"). A day is exactly 24h.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexByte(s, 'd')
	if i < 0 {
		return time.ParseDuration(s)
	}
	num := s[:i]
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || num == "" || strings.Trim(num, "0123456789.") != "" || n*float64(day) > float64(1<<62) {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	d := time.Duration(n * float64(day))
	if rest := s[i+1:]; rest != "" {
		r, err := time.ParseDuration(rest)
		if err != nil || r < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d += r
	}
	return d, nil
}

// durationValue is a flag.Value backed by ParseDuration.
type durationValue time.Duration

func (d *durationValue) Set(s string) error {
	v, err := ParseDuration(s)
	if err != nil {
		return err
	}
	*d = durationValue(v)
	return nil
}

func (d *durationValue) String() string {
	v := time.Duration(*d)
	if v != 0 && v%day == 0 {
		return fmt.Sprintf("%dd", v/day)
	}
	return v.String()
}

// Duration defines a duration flag on fs that, unlike flag.Duration, also
// accepts a day suffix (see ParseDuration).
func Duration(fs *flag.FlagSet, name string, value time.Duration, usage string) *time.Duration {
	p := new(time.Duration)
	*p = value
	fs.Var((*durationValue)(p), name, usage)
	return p
}
