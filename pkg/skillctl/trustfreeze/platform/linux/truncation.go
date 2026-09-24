package linux

import (
	"fmt"

	"github.com/kamir/m3c-tools/pkg/skillctl/trustfreeze/probe"
)

// A byte cap on the output of a tool is a cap on what the capture knows. The
// runner records that it cut a stream (probe.CommandResult.StdoutTruncated);
// a probe that reads the cut stream as if it were whole turns a prefix of the
// host into a statement about the host. Every probe of this package therefore
// asks what it lost, records it as one diagnostic that names the stream and
// the cap, and drops to partial: a cut list is an incomplete list, never a
// captured one (SPEC-0471 TF06-R2, playbook L1).

// netDiagVolumeCapped marks the objects a per probe volume cap dropped. The
// count of the objects that were seen stays true; the artifacts stop at the
// cap (playbook L6).
const netDiagVolumeCapped = "volume_capped"

// outputCap returns the stdout and stderr caps of this run, so a diagnostic
// can name the number that cut the answer instead of alluding to it.
func outputCap(cc probe.CollectContext) (stdout, stderr int64) {
	l := cc.Limits.WithDefaults()
	return l.MaxStdoutBytes, l.MaxStderrBytes
}

// truncationNote builds the message of one cut stream: which tool, which
// stream, how much of how much survived, which cap cut it, and what the
// bundle therefore does not know.
func truncationNote(tool, stream string, kept int, printed, capBytes int64, consequence string) string {
	return fmt.Sprintf("the output limit of %d bytes cut the %s of %s: %d of %d bytes were read; %s",
		capBytes, stream, tool, kept, printed, consequence)
}
