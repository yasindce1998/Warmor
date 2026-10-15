package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCRIOHookConfigs checks the shipped CRI-O hook definitions
// (deploy/crio/*.json, OCI hooks schema 1.0.0): every stage must pass the
// action this binary handles for it, since one file's args apply to all of
// its stages.
func TestCRIOHookConfigs(t *testing.T) {
	wantAction := map[string]string{
		"prestart":        "start",
		"createRuntime":   "start",
		"createContainer": "start",
		"startContainer":  "start",
		"poststart":       "start",
		"poststop":        "stop",
	}
	files, err := filepath.Glob(filepath.Join("..", "..", "deploy", "crio", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no hook configs found: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cfg struct {
			Version string `json:"version"`
			Hook    struct {
				Path string   `json:"path"`
				Args []string `json:"args"`
			} `json:"hook"`
			When   map[string]any `json:"when"`
			Stages []string       `json:"stages"`
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Errorf("%s: invalid JSON: %v", f, err)
			continue
		}
		if cfg.Version != "1.0.0" || cfg.Hook.Path == "" || len(cfg.When) == 0 || len(cfg.Stages) == 0 {
			t.Errorf("%s: incomplete hook config: %+v", f, cfg)
		}
		action := ""
		for i, a := range cfg.Hook.Args {
			if a == "--action" && i+1 < len(cfg.Hook.Args) {
				action = cfg.Hook.Args[i+1]
			}
		}
		for _, s := range cfg.Stages {
			want, ok := wantAction[s]
			if !ok {
				t.Errorf("%s: unknown stage %q", f, s)
				continue
			}
			if action != want {
				t.Errorf("%s: stage %s passes --action %q, want %q", f, s, action, want)
			}
			seen[want] = true
		}
	}
	if !seen["start"] || !seen["stop"] {
		t.Errorf("hook configs must cover both bind (start) and unbind (stop); covered: %v", seen)
	}
}
