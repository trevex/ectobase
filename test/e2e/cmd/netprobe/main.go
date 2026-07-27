// Command netprobe is a cgo-free network probe CLI that replaces scapy-based
// harnesses with pure-Go packet I/O. Subcommands dispatch to individual probe
// implementations backed by the netpkt package.
package main

import (
	"fmt"
	"os"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: netprobe <pcap-verify|send|send-sniff|pcap-replay> [flags]")
		return 2
	}
	switch args[0] {
	case "pcap-verify":
		return pcapVerify(args[1:])
	case "send":
		return sendCmd(args[1:])
	case "pcap-replay":
		return pcapReplay(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", args[0])
		return 2
	}
}
