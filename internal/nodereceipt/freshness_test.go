package nodereceipt

import (
	"testing"
	"time"
)

func TestReceiptFreshnessUsesChallengeServerAndMeasurementClocks(t *testing.T) {
	now := time.Now()
	age := time.Minute
	for _, tc := range []struct {
		name                        string
		expires, received, measured time.Time
		want                        bool
	}{
		{"fresh", now.Add(age), now, now, true},
		{"expired-challenge", now, now, now, false},
		{"old-server-receive", now.Add(age), now.Add(-age), now, false},
		{"old-measurement", now.Add(age), now, now.Add(-age), false},
		{"server-clock-went-back", now.Add(age), now.Add(time.Second), now, false},
		{"future-client-clock", now.Add(age), now, now.Add(6 * time.Second), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := &session{challenge: Challenge{ExpiresAt: tc.expires}, received: tc.received, receipt: &Receipt{MeasuredAt: tc.measured}}
			if v.fresh(now, age) != tc.want {
				t.Fatalf("fresh=%t want %t", v.fresh(now, age), tc.want)
			}
		})
	}
	if (*session)(nil).fresh(now, age) || (&session{}).fresh(now, age) {
		t.Fatal("missing receipt is fresh")
	}
}
