package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/trevex/ectobase/test/e2e/internal/netpkt"
)

// pcapReplay implements the "pcap-replay" subcommand: read frames from an input pcap,
// replay them on an interface, and optionally capture responses to an output pcap.
func pcapReplay(args []string) int {
	fs := flag.NewFlagSet("pcap-replay", flag.ContinueOnError)

	inPath := fs.String("in", "", "input pcap to replay (required)")
	iface := fs.String("iface", "", "TX interface (required)")
	outPath := fs.String("out", "", "optional output pcap for captured frames")
	sniffIface := fs.String("sniff-iface", "", "interface to sniff on (default = --iface)")
	timeoutSec := fs.Float64("timeout", 3, "capture timeout in seconds")
	countExpect := fs.Int("count-expect", 0, "if >0, exit non-zero unless at least this many frames are captured")
	repeat := fs.Int("repeat", 1, "number of times to replay all input frames (>=1)")
	repeatIntervalMs := fs.Int("repeat-interval-ms", 0, "milliseconds to sleep between each repeat")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *inPath == "" {
		fmt.Fprintln(os.Stderr, "pcap-replay: --in is required")
		return 2
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "pcap-replay: --iface is required")
		return 2
	}
	if *sniffIface == "" {
		*sniffIface = *iface
	}

	// Read input frames from pcap.
	inPkts, err := netpkt.ReadPcap(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap-replay: read --in %q: %v\n", *inPath, err)
		return 1
	}

	// Collect raw frame bytes for replay.
	frames := make([][]byte, 0, len(inPkts))
	for _, pkt := range inPkts {
		frames = append(frames, pkt.Data())
	}

	// replayAll sends all frames --repeat times with --repeat-interval-ms between rounds.
	replayAll := func() error {
		rpt := max(*repeat, 1)
		for r := range rpt {
			for _, data := range frames {
				if err := netpkt.Send(*iface, data); err != nil {
					return err
				}
			}
			if *repeatIntervalMs > 0 && r < rpt-1 {
				time.Sleep(time.Duration(*repeatIntervalMs) * time.Millisecond)
			}
		}
		return nil
	}

	if *outPath == "" {
		// Pure replay: no capture.
		if err := replayAll(); err != nil {
			fmt.Fprintf(os.Stderr, "pcap-replay: send: %v\n", err)
			return 1
		}
		rpt := max(*repeat, 1)
		fmt.Printf("replayed %d frame(s) from %s on %s\n", len(frames)*rpt, *inPath, *iface)
		return 0
	}

	// Replay + capture mode.
	timeout := time.Duration(float64(time.Second) * *timeoutSec)

	arm := func() error {
		return replayAll()
	}

	// match always returns false so we collect until timeout.
	match := func(_ gopacket.Packet) bool { return false }

	captured, err := netpkt.Sniff(*sniffIface, timeout, arm, match)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pcap-replay: sniff: %v\n", err)
		return 1
	}

	// Gather raw bytes for writing.
	capturedRaw := make([][]byte, 0, len(captured))
	for _, pkt := range captured {
		capturedRaw = append(capturedRaw, pkt.Data())
	}

	if err := netpkt.WritePcap(*outPath, capturedRaw); err != nil {
		fmt.Fprintf(os.Stderr, "pcap-replay: write --out %q: %v\n", *outPath, err)
		return 1
	}

	fmt.Printf("replayed %d frame(s) from %s on %s\n", len(frames), *inPath, *iface)
	fmt.Printf("captured %d frame(s) -> %s\n", len(captured), *outPath)

	if *countExpect > 0 && len(captured) < *countExpect {
		fmt.Fprintf(os.Stderr, "pcap-replay: captured %d frame(s), want >= %d\n", len(captured), *countExpect)
		return 1
	}

	return 0
}
