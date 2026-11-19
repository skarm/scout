//go:build unix

package replay //nolint:testpackage // Exercises materialization before filesystem metadata can enter a scan.

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReplayRejectsLostExecutableMetadata(t *testing.T) {
	if os.Getenv("SCOUT_REPLAY_METADATA_CHILD") == "1" {
		directory := t.TempDir()
		previous := unix.Umask(0o100)
		defer unix.Umask(previous)
		// Create the directory before the restrictive mask is set.
		// This models a filesystem that cannot preserve captured executable bits.
		if err := writeCapturedFile(directory, capturedFile{name: "handler", data: []byte("printf ready\n"), executable: true}); err == nil {
			t.Fatal("lost executable metadata was accepted as a faithful capture")
		}
		return
	}

	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), binary, "-test.run=^TestReplayRejectsLostExecutableMetadata$")
	command.Env = append(os.Environ(), "SCOUT_REPLAY_METADATA_CHILD=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("metadata admission: %v\n%s", err, output)
	}
}
