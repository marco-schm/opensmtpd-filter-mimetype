package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDebugLogsDoNotContainMail(t *testing.T) {
	if os.Getenv("MIMEFILTER_TEST_HELPER") == "1" {
		os.Args = []string{"mimefilter", "-config", os.Getenv("MIMEFILTER_TEST_CONFIG")}
		main()
		return
	}
	config := filepath.Join(t.TempDir(), "filter.yaml")
	if err := os.WriteFile(config, []byte("log_level: debug\nallowed_mime_types: [text/plain]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	const secret = "unique-private-mail-content-4219"
	input := strings.Join([]string{
		"config|smtpd-version|7.9.0",
		"config|protocol|0.8",
		"config|ready",
		"filter|0.8|1|smtp-in|data-line|s1|t1|Subject: private",
		"filter|0.8|1|smtp-in|data-line|s1|t1|Content-Type: text/plain",
		"filter|0.8|1|smtp-in|data-line|s1|t1|",
		"filter|0.8|1|smtp-in|data-line|s1|t1|" + secret,
		"filter|0.8|1|smtp-in|data-line|s1|t1|.",
		"filter|0.8|1|smtp-in|commit|s1|t2",
	}, "\n") + "\n"
	cmd := exec.Command(os.Args[0], "-test.run=^TestDebugLogsDoNotContainMail$")
	cmd.Env = append(os.Environ(), "MIMEFILTER_TEST_HELPER=1", "MIMEFILTER_TEST_CONFIG="+config)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("filter failed: %v; stderr=%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), secret) || strings.Contains(stderr.String(), "Subject: private") {
		t.Fatalf("debug log contains message content: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "filter-result|s1|t2|proceed") {
		t.Fatalf("filter did not complete: %s", stdout.String())
	}
}
