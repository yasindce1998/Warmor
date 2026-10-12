package winutil

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yasindce1998/warmor/pkg/api"
)

func TestCommFromPath(t *testing.T) {
	cases := map[string]string{
		`C:\Windows\System32\WindowsPowerShell\v1.0\PowerShell.EXE`: "powershell.exe",
		`\Device\HarddiskVolume3\Windows\System32\cmd.exe`:          "cmd.exe",
		`notepad.exe`:    "notepad.exe",
		`C:/tools/x.exe`: "x.exe",
		``:               "",
	}
	for in, want := range cases {
		if got := CommFromPath(in); got != want {
			t.Errorf("CommFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitCommandLine(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{``, nil},
		{`cmd.exe`, []string{"cmd.exe"}},
		{`"C:\Program Files\x.exe" -a  b`, []string{`C:\Program Files\x.exe`, "-a", "b"}},
		{`powershell.exe -enc SQBFAFgA`, []string{"powershell.exe", "-enc", "SQBFAFgA"}},
		// Backslashes in the program name are literal.
		{`C:\a\b.exe "x y"`, []string{`C:\a\b.exe`, "x y"}},
		// MSVC rules: 2n backslashes + quote, 2n+1 backslashes + quote.
		{`p a\\"b c"`, []string{"p", `a\b c`}},
		{`p a\\\"b`, []string{"p", `a\"b`}},
		{`p a\\b`, []string{"p", `a\\b`}},
		{`p "a""b"`, []string{"p", `a"b`}},
		{"p\ta\t\tb ", []string{"p", "a", "b"}},
	}
	for _, c := range cases {
		if got := SplitCommandLine(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("SplitCommandLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDevicePathMapRoundTrip(t *testing.T) {
	m := NewDevicePathMap(map[string]string{
		"C:": `\Device\HarddiskVolume1`,
		"D:": `\Device\HarddiskVolume10`,
	})

	cases := map[string]string{
		`\Device\HarddiskVolume1\Windows\System32\cmd.exe`: `C:\Windows\System32\cmd.exe`,
		`\Device\HarddiskVolume10\data\x.txt`:              `D:\data\x.txt`,
		`\device\harddiskvolume1\Users`:                    `C:\Users`,
		`\Device\HarddiskVolume1`:                          `C:\`,
		`\??\C:\temp\a.exe`:                                `C:\temp\a.exe`,
		`\Device\Mup\server\share\f`:                       `\Device\Mup\server\share\f`,
		// Must not match a device that is only a string prefix.
		`\Device\HarddiskVolume100\x`: `\Device\HarddiskVolume100\x`,
	}
	for nt, want := range cases {
		got := m.TranslateImage(nt)
		if got != want {
			t.Errorf("Translate(%q) = %q, want %q", nt, got, want)
		}
		// Anything observed must map back to exactly the bytes the kernel saw.
		if back := m.Untranslate(got); back != nt {
			t.Errorf("Untranslate(Translate(%q)) = %q", nt, back)
		}
	}

	// Plain Translate does not record: file paths must not evict images.
	m.Translate(`\Device\HarddiskVolume1\file-only.txt`)
	if _, ok := m.reverse[strings.ToLower(`C:\file-only.txt`)]; ok {
		t.Error("Translate must not record file paths")
	}

	// Never observed: prefix substitution, case-insensitive drive.
	if got := m.Untranslate(`d:\new\file`); got != `\Device\HarddiskVolume10\new\file` {
		t.Errorf("Untranslate fallback = %q", got)
	}
	if got := m.Untranslate(`\\server\share`); got != `\\server\share` {
		t.Errorf("Untranslate(UNC) = %q", got)
	}
}

func TestDevicePathMapReverseBounded(t *testing.T) {
	m := NewDevicePathMap(map[string]string{"C:": `\Device\HarddiskVolume1`})
	for i := 0; i < maxReverseEntries+100; i++ {
		m.TranslateImage(`\Device\HarddiskVolume1\f` + strings.Repeat("x", i%50) + string(rune('a'+i%26)) + strconv.Itoa(i))
	}
	if len(m.reverse) > maxReverseEntries || len(m.reverseOrder) > maxReverseEntries {
		t.Fatalf("reverse cache grew to %d/%d", len(m.reverse), len(m.reverseOrder))
	}
}

func TestImageHash(t *testing.T) {
	a := ImageHash(`\Device\HarddiskVolume1\Windows\System32\CMD.EXE`)
	b := ImageHash(`\device\harddiskvolume1\windows\system32\cmd.exe`)
	if a == 0 || a != b {
		t.Fatalf("hash must be non-zero and ASCII case-insensitive: %x vs %x", a, b)
	}
	if ImageHash(`\Device\HarddiskVolume1\Windows\System32\cmd2.exe`) == a {
		t.Fatal("different paths hashed equal")
	}
	if ImageHash("") != 0 {
		t.Fatal("empty path must hash to 0")
	}
	if ImageHash(strings.Repeat("a", ImagePathMaxChars)) != 0 {
		t.Fatal("paths that fill the kernel buffer must hash to 0")
	}
	// Golden value: FNV-1a 64 over UTF-16LE "a" = bytes 0x61 0x00.
	h := uint64(fnv64Offset)
	h ^= 0x61
	h *= fnv64Prime
	h ^= 0
	h *= fnv64Prime
	if got := ImageHash("A"); got != h {
		t.Fatalf("ImageHash(A) = %x, want %x", got, h)
	}
}

func TestProcTable(t *testing.T) {
	now := time.Unix(1000, 0)
	pt := NewProcTable()
	pt.now = func() time.Time { return now }

	pt.Put(ProcInfo{PID: 10, Comm: "a.exe", CreateTime: now})
	if p, ok := pt.Get(10); !ok || p.Comm != "a.exe" {
		t.Fatalf("Get = %+v %v", p, ok)
	}

	pt.Exit(10)
	if _, ok := pt.Get(10); !ok {
		t.Fatal("exited process must stay resolvable during grace")
	}

	now = now.Add(exitGrace + time.Second)
	pt.Exit(999) // triggers sweep
	if _, ok := pt.Get(10); ok {
		t.Fatal("exited process must be swept after grace")
	}

	// PID reuse replaces the old process and clears its exit mark.
	pt.Put(ProcInfo{PID: 11, Comm: "old.exe", CreateTime: now})
	pt.Exit(11)
	pt.Put(ProcInfo{PID: 11, Comm: "new.exe", CreateTime: now})
	now = now.Add(exitGrace + time.Second)
	pt.Exit(999)
	if p, ok := pt.Get(11); !ok || p.Comm != "new.exe" {
		t.Fatalf("reused pid = %+v %v", p, ok)
	}
}

func TestProcTableBounded(t *testing.T) {
	pt := NewProcTable()
	base := time.Unix(0, 0)
	for i := 0; i < maxProcEntries+10; i++ {
		pt.Put(ProcInfo{PID: uint32(i), CreateTime: base.Add(time.Duration(i) * time.Second)})
	}
	if pt.Len() > maxProcEntries {
		t.Fatalf("table grew to %d", pt.Len())
	}
	// The newest process must survive eviction.
	if _, ok := pt.Get(uint32(maxProcEntries + 9)); !ok {
		t.Fatal("newest process evicted")
	}
}

func TestProcessEvent(t *testing.T) {
	ts := time.Unix(5, 0)
	ev := ProcessEvent(ProcInfo{
		PID:     7,
		Comm:    "powershell.exe",
		Image:   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		CmdLine: `powershell.exe -enc SQBFAFgA`,
	}, ts)
	if ev.GetType() != api.EventTypeProcess || ev.PID != 7 || ev.Comm != "powershell.exe" ||
		ev.Process.Filename != ev.Filename || !ev.Timestamp.Equal(ts) {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if !reflect.DeepEqual(ev.Process.Args, []string{"powershell.exe", "-enc", "SQBFAFgA"}) {
		t.Fatalf("args = %q", ev.Process.Args)
	}
}
