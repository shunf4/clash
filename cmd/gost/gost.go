package gost

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/metacubex/mihomo/common/guard"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/listener"
	"github.com/metacubex/mihomo/log"
)

// Main is the entry point of `mhm gost`, invoked from main.go with the
// arguments after the subcommand name.
func Main(args []string) {
	opts, err := parseArgs(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Print(usage)
			return
		}
		fmt.Fprintf(os.Stderr, "mhm gost: %s\n\n%s", err.Error(), usage)
		os.Exit(2)
	}
	if opts.helpRequested {
		fmt.Print(usage)
		return
	}

	applyGuard(opts)

	entry, err := buildEntry(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mhm gost: %s\n", err.Error())
		os.Exit(1)
	}

	if opts.dryRun {
		if err := entry.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "mhm gost: verify generated configuration failed: %s\n", err.Error())
			os.Exit(1)
		}
		out, err := entry.Render()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mhm gost: %s\n", err.Error())
			os.Exit(1)
		}
		fmt.Print(out)
		return
	}

	printWarnings(entry)

	if err := hub.Parse(entry.config); err != nil {
		log.Errorln("mhm gost: load generated config error: %s", err.Error())
		os.Exit(1)
	}
	// The generated configuration is complete and must never fall back to the
	// on-disk configuration when this process is reloaded by a SIGHUP.
	entry.config = nil
	verifyListener(entry)

	termSign := make(chan os.Signal, 1)
	signal.Notify(termSign, syscall.SIGINT, syscall.SIGTERM)
	<-termSign
	executor.Shutdown()
}

// applyGuard installs the process-wide disk/network policy.
func applyGuard(opts *options) {
	if !opts.diskAllowed {
		guard.DisableDisk()
	}
	if !opts.netAllowed {
		guard.DisableNet()
	}
}

// printWarnings prints the startup banner and the warnings the user must be
// aware of before the listener starts.
func printWarnings(e *Entry) {
	for _, warning := range e.Warnings() {
		log.Warnln("mhm gost: %s", warning)
	}
	log.Infoln("mhm gost: inbound=%s (%s) disk=%s net=%s", e.Name, e.Type, allowText(guard.DiskAllowed()), allowText(guard.NetAllowed()))
}

func allowText(allowed bool) string {
	if allowed {
		return "allow"
	}
	return "deny"
}

// options is the parsed command line of the gost subcommand.
type options struct {
	inbound       string
	outbound      string
	diskAllowed   bool
	netAllowed    bool
	dryRun        bool
	helpRequested bool
}

// parseArgs parses the subcommand flags. -L/-F are single valued by design: a
// single inbound and a single outbound in this version.
func parseArgs(args []string) (*options, error) {
	opts := &options{}
	fs := flag.NewFlagSet("gost", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // errors and usage are printed by Main
	fs.Usage = func() {}

	var inbound, outbound string
	fs.StringVar(&inbound, "L", "", "inbound listener (URL or YAML fragment)")
	fs.StringVar(&outbound, "F", "", "upstream outbound (URL or YAML fragment), omitted means direct")
	fs.StringVar(&inbound, "listen", "", "alias of -L")
	fs.StringVar(&outbound, "forward", "", "alias of -F")
	fs.StringVar(&inbound, "l", "", "alias of -L")
	fs.StringVar(&outbound, "f", "", "alias of -F")
	disk := fs.String("disk", "deny", "allow mihomo to write to the disk: deny|allow")
	netw := fs.String("net", "deny", "allow mihomo initiated network access: deny|allow")
	dryRun := fs.Bool("dry-run", false, "print the generated configuration and exit")
	help := fs.Bool("h", false, "show help")
	helpLong := fs.Bool("help", false, "show help")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if *help || *helpLong {
		opts.helpRequested = true
		return opts, nil
	}

	// -L is mandatory in the short form; a lone positional YAML fragment is
	// accepted as well because shell quoting multi-line strings is easier
	// without a flag in front of them.
	rest := fs.Args()
	switch {
	case inbound != "" && len(rest) > 0:
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(rest, " "))
	case inbound != "":
		opts.inbound = inbound
	case len(rest) == 1:
		opts.inbound = rest[0]
	case len(rest) > 1:
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(rest, " "))
	}
	if strings.TrimSpace(opts.inbound) == "" {
		return nil, errors.New("missing inbound, use -L <url|yaml>")
	}
	opts.outbound = outbound
	if err := parseAllowFlag("--disk", *disk, &opts.diskAllowed); err != nil {
		return nil, err
	}
	if err := parseAllowFlag("--net", *netw, &opts.netAllowed); err != nil {
		return nil, err
	}
	opts.dryRun = *dryRun
	return opts, nil
}

func parseAllowFlag(name, value string, target *bool) error {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow":
		*target = true
	case "deny":
		*target = false
	default:
		return fmt.Errorf("invalid value %q for %s, expected deny or allow", value, name)
	}
	return nil
}

// verifyListener makes sure the inbound listener is actually serving. The core
// only logs listener failures (for example a port already in use), so a silent
// failure here would leave a "running" process that forwards nothing.
func verifyListener(entry *Entry) {
	addr := listenerAddress(entry.Name)
	if addr != "" {
		log.Infoln("mhm gost: inbound[%s] (%s) listening at %s", entry.Name, entry.Type, addr)
		return
	}
	log.Errorln("mhm gost: inbound[%s] failed to listen, see the errors above (port already in use?)", entry.Name)
	executor.Shutdown()
	os.Exit(1)
}

// listenerAddress returns the address the named listener is serving on, or an
// empty string when the listener was not created or failed to listen.
func listenerAddress(name string) string {
	l, ok := listener.GetInboundListener(name)
	if !ok || l == nil {
		return ""
	}
	return l.Address()
}
