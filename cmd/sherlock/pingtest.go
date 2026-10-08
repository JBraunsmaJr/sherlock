package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"sherlock/internal/platform"
)

// pingtest runs Sherlock's own pinger against one target and prints every
// result, so it can be compared line by line with the OS ping command.
// By default it also pings the gateway at the same instant, exactly like the
// monitor does, to expose any interference between simultaneous probes.
func pingtest(args []string) error {
	fs := flag.NewFlagSet("pingtest", flag.ExitOnError)
	count := fs.Int("n", 60, "number of pings")
	interval := fs.Duration("i", time.Second, "interval between pings")
	timeout := fs.Duration("t", 900*time.Millisecond, "timeout per ping (the monitor uses 900ms)")
	alone := fs.Bool("alone", false, "don't ping the gateway alongside the target")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sherlock pingtest [-n 60] [-i 1s] [-t 900ms] [-alone] [target]")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	target := "1.1.1.1"
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	ip := net.ParseIP(target)
	if ip == nil {
		return fmt.Errorf("%q is not an IP address", target)
	}
	p, err := platform.NewPinger(ip)
	if err != nil {
		return err
	}
	defer p.Close()

	var gw platform.Pinger
	var gwIP net.IP
	if !*alone {
		if gwIP, _, err = platform.DefaultGateway(""); err == nil {
			if gw, err = platform.NewPinger(gwIP); err == nil {
				defer gw.Close()
			}
		}
		if err != nil {
			fmt.Printf("(no gateway pinger: %v; running alone)\n", err)
			gw = nil
		}
	}
	if gw != nil {
		fmt.Printf("Pinging %s and gateway %s together, %d times, timeout %s\n\n", target, gwIP, *count, *timeout)
	} else {
		fmt.Printf("Pinging %s alone, %d times, timeout %s\n\n", target, *count, *timeout)
	}

	var rtts []float64
	failures := map[string]int{}
	gwFail := 0
	t := time.NewTicker(*interval)
	defer t.Stop()
	for i := 1; i <= *count; i++ {
		if i > 1 {
			<-t.C
		}
		var wg sync.WaitGroup
		var gwRTT time.Duration
		var gwErr error
		if gw != nil {
			wg.Add(1)
			go func() { defer wg.Done(); gwRTT, gwErr = gw.Ping(*timeout) }()
		}
		rtt, err := p.Ping(*timeout)
		wg.Wait()

		line := fmt.Sprintf("%3d  %s  ", i, time.Now().Format("15:04:05.000"))
		if err != nil {
			kind := err.Error()
			if errors.Is(err, platform.ErrTimeout) {
				kind = "timed out"
			}
			failures[kind]++
			line += fmt.Sprintf("%-8s FAIL  %s", target, kind)
		} else {
			ms := float64(rtt.Microseconds()) / 1000
			rtts = append(rtts, ms)
			line += fmt.Sprintf("%-8s %7.2f ms", target, ms)
		}
		if gw != nil {
			if gwErr != nil {
				gwFail++
				line += fmt.Sprintf("   | gateway FAIL %v", gwErr)
			} else {
				line += fmt.Sprintf("   | gateway %.2f ms", float64(gwRTT.Microseconds())/1000)
			}
		}
		fmt.Println(line)
	}

	fmt.Printf("\n%s: %d sent, %d answered, %d failed\n", target, *count, len(rtts), *count-len(rtts))
	if len(rtts) > 0 {
		sort.Float64s(rtts)
		sum := 0.0
		for _, v := range rtts {
			sum += v
		}
		fmt.Printf("  rtt min %.2f / median %.2f / max %.2f ms (avg %.2f)\n",
			rtts[0], rtts[len(rtts)/2], rtts[len(rtts)-1], sum/float64(len(rtts)))
	}
	for kind, n := range failures {
		fmt.Printf("  %dx %s\n", n, kind)
	}
	if gw != nil {
		fmt.Printf("gateway: %d failed\n", gwFail)
	}
	return nil
}
