// SPDX-License-Identifier: GPL-2.0-only
// tquicctl - CLI tool for controlling the TQUIC kernel module via genetlink

package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"

	nl "github.com/linux/tquicd/netlink"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  tquicctl path-add <conn_id> <ifindex> <local_ip> <remote_ip>\n")
	fmt.Fprintf(os.Stderr, "  tquicctl path-remove <path_id>\n")
	fmt.Fprintf(os.Stderr, "  tquicctl path-list [conn_id]\n")
	fmt.Fprintf(os.Stderr, "  tquicctl stats [conn_id]\n")
	fmt.Fprintf(os.Stderr, "  tquicctl sched-get <conn_id>\n")
	fmt.Fprintf(os.Stderr, "  tquicctl sched-set <conn_id> <name>\n")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	client, err := nl.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to TQUIC kernel module: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	cmd := os.Args[1]

	switch cmd {
	case "path-add":
		if len(os.Args) < 6 {
			fmt.Fprintf(os.Stderr, "Usage: tquicctl path-add <conn_id> <ifindex> <local_ip> <remote_ip>\n")
			os.Exit(1)
		}
		connID, _ := strconv.ParseUint(os.Args[2], 10, 64)
		ifindex, _ := strconv.ParseInt(os.Args[3], 10, 32)
		localIP := net.ParseIP(os.Args[4])
		remoteIP := net.ParseIP(os.Args[5])

		if localIP == nil || remoteIP == nil {
			fmt.Fprintf(os.Stderr, "Invalid IP addresses\n")
			os.Exit(1)
		}

		family := uint16(syscall.AF_INET)
		if localIP.To4() == nil {
			family = syscall.AF_INET6
		}

		fmt.Printf("Adding path for conn %d: ifindex=%d local=%s remote=%s\n",
			connID, ifindex, localIP, remoteIP)

		err := client.AddPath(connID, int32(ifindex), localIP, remoteIP, family)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add path: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Path added successfully!")

	case "path-remove":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: tquicctl path-remove <path_id>\n")
			os.Exit(1)
		}
		pathID, _ := strconv.ParseUint(os.Args[2], 10, 32)

		err := client.RemovePath(uint32(pathID))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to remove path: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Path removed successfully!")

	case "path-list":
		connID := uint64(0)
		if len(os.Args) > 2 {
			connID, _ = strconv.ParseUint(os.Args[2], 10, 64)
		}

		paths, err := client.ListPathsForConn(connID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to list paths: %v\n", err)
			os.Exit(1)
		}

		if len(paths) == 0 {
			fmt.Println("No paths found")
			return
		}

		for _, p := range paths {
			fmt.Printf("Path %d: state=%s ifindex=%d rtt=%dus loss=%.2f%% weight=%d\n",
				p.PathID, p.StateName(), p.Ifindex, p.RTT, p.LossRatio()*100, p.Weight)
			if p.LocalIP != nil {
				fmt.Printf("  Local:  %s:%d\n", p.LocalIP, p.LocalPort)
			}
			if p.RemoteIP != nil {
				fmt.Printf("  Remote: %s:%d\n", p.RemoteIP, p.RemotePort)
			}
		}

	case "stats":
		connID := uint64(0)
		if len(os.Args) > 2 {
			connID, _ = strconv.ParseUint(os.Args[2], 10, 64)
		}

		stats, err := client.GetStatsForConn(connID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get stats: %v\n", err)
			os.Exit(1)
		}

		if len(stats) == 0 {
			fmt.Println("No stats available")
			return
		}

		for _, s := range stats {
			fmt.Printf("Path %d: tx=%d/%d rx=%d/%d retrans=%d srtt=%dus cwnd=%d\n",
				s.PathID, s.TxBytes, s.TxPackets, s.RxBytes, s.RxPackets,
				s.Retrans, s.SRTT, s.Cwnd)
		}

	case "sched-get":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: tquicctl sched-get <conn_id>\n")
			os.Exit(1)
		}
		connID, _ := strconv.ParseUint(os.Args[2], 10, 64)
		name, err := client.GetScheduler(connID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get scheduler: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Current scheduler: %s\n", name)

	case "sched-set":
		if len(os.Args) < 4 {
			fmt.Fprintf(os.Stderr, "Usage: tquicctl sched-set <conn_id> <name>\n")
			os.Exit(1)
		}
		connID, _ := strconv.ParseUint(os.Args[2], 10, 64)
		err := client.SetScheduler(connID, os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to set scheduler: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Scheduler set to: %s\n", os.Args[3])

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", cmd)
		usage()
	}
}
