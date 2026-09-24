// Command kubeshield scans Kubernetes manifests for security
// misconfigurations.
//
//	kubeshield scan ./deploy
//	helm template mychart | kubeshield scan -
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sriharifortitude/kubeshield/internal/manifest"
	"github.com/sriharifortitude/kubeshield/internal/report"
	"github.com/sriharifortitude/kubeshield/internal/rules"
	"github.com/sriharifortitude/kubeshield/internal/waiver"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 || args[0] != "scan" {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	fs := newFlagSet()
	if err := fs.Parse(args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "scan: expected exactly one path (a file, a directory, or - for stdin)")
		return 2
	}

	resources, err := loadManifests(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	var w waiver.File
	if fs.waivers != "" {
		data, err := os.ReadFile(fs.waivers)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s: %s\n", fs.waivers, err)
			return 2
		}
		parsed, err := waiver.Parse(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %s\n", fs.waivers, err)
			return 2
		}
		w = *parsed
	}

	threshold, err := parseSeverity(fs.failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	findings := rules.RunAll(resources)
	rows := make([]report.Row, 0, len(findings))
	today := time.Now()
	for _, f := range findings {
		outcome, entry := w.Apply(f, today)
		rows = append(rows, report.Row{Finding: f, WaiverOutcome: outcome, Waiver: entry})
	}
	result := report.NewResult(rows)

	out, err := render(result, fs.format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rendering %s report: %s\n", fs.format, err)
		return 2
	}
	if err := write(out, fs.output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if fs.output != "" && fs.format != "terminal" {
		fmt.Print(report.Terminal(result))
	}

	if len(result.Failing(threshold)) > 0 {
		return 1
	}
	return 0
}

// loadManifests reads path -- a single file, a directory (walked
// recursively for .yaml/.yml files), or "-" for stdin -- and parses
// every YAML document in it.
func loadManifests(path string) ([]manifest.Resource, error) {
	if path == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return manifest.Parse(data, "-")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var files []string
	if info.IsDir() {
		err := filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if ext := strings.ToLower(filepath.Ext(p)); ext == ".yaml" || ext == ".yml" {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walking %s: %w", path, err)
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s: no .yaml or .yml files found", path)
		}
	} else {
		files = []string{path}
	}

	var resources []manifest.Resource
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", f, err)
		}
		parsed, err := manifest.Parse(data, f)
		if err != nil {
			return nil, err
		}
		resources = append(resources, parsed...)
	}
	return resources, nil
}

func render(r report.Result, format string) (string, error) {
	switch format {
	case "terminal", "":
		return report.Terminal(r), nil
	case "json":
		b, err := report.JSON(r)
		return string(b) + "\n", err
	case "sarif":
		b, err := report.SARIF(r)
		return string(b) + "\n", err
	default:
		return "", fmt.Errorf("unknown format %q: expected terminal, json or sarif", format)
	}
}

func write(text, path string) error {
	if path == "" {
		fmt.Print(text)
		return nil
	}
	return os.WriteFile(path, []byte(text), 0o644)
}

func parseSeverity(s string) (rules.Severity, error) {
	switch s {
	case "low", "":
		return rules.Low, nil
	case "medium":
		return rules.Medium, nil
	case "high":
		return rules.High, nil
	case "critical":
		return rules.Critical, nil
	default:
		return "", fmt.Errorf("--fail-on: expected low, medium, high or critical, got %q", s)
	}
}

const usage = `usage: kubeshield scan [--format terminal|json|sarif] [--output FILE] [--fail-on low|medium|high|critical] [--waivers FILE] <path|->`
