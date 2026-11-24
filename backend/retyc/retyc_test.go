// Test Retyc filesystem interface
package retyc

import (
	"testing"

	"github.com/rclone/rclone/fstest/fstests"
)

// TestIntegration runs integration tests against the remote
//
// Rclone can't create storage spaces, so the tests run in a directory of
// a storage space called "rclone" which must exist in the account of the
// TestRetyc remote. Make it with Retyc before running the tests.
func TestIntegration(t *testing.T) {
	fstests.Run(t, &fstests.Opt{
		RemoteName: "TestRetyc:rclone",
		NilObject:  (*Object)(nil),
	})
}
