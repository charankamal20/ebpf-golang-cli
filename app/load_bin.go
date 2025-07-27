package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const EBPF_PROG_FILE = "xdp-drop.o"

func main() {
    if len(os.Args) != 2 {
        fmt.Println("Invalid args, please give a valid port number")
        os.Exit(1)
    }

	port64, err := strconv.ParseUint(os.Args[1], 10, 16)
    if err != nil || port64 == 0 {
        fmt.Printf("Invalid port number: %s\n", os.Args[1])
        fmt.Println("Port must be between 1-65535")
        os.Exit(1)
    }
    port := uint16(port64)

    // Remove memory limit for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Printf("Failed to remove memlock: %v\n", err)
        os.Exit(1)
    }

    // Load the eBPF collection from the object file
    spec, err := ebpf.LoadCollectionSpec(EBPF_PROG_FILE)
    if err != nil {
        fmt.Printf("Failed to load collection spec from %s: %+v\n", EBPF_PROG_FILE, err)
        os.Exit(1)
    }

    // Create the collection (loads programs and maps into kernel)
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        fmt.Printf("Failed to create collection: %v\n", err)
        os.Exit(1)
    }
    defer coll.Close()

    fmt.Printf("✓ Successfully loaded eBPF binary: %s\n", EBPF_PROG_FILE)

	blockedPortMap := coll.Maps["blocked_port_map"]
    if blockedPortMap == nil {
        fmt.Println("Error: blocked_port_map not found in the eBPF program")
        os.Exit(1)
    }

	key := uint32(0)
    if err := blockedPortMap.Update(key, port, ebpf.UpdateAny); err != nil {
        fmt.Printf("Failed to update blocked port: %v\n", err)
        os.Exit(1)
    }

	// Find and attach XDP program
	var xdpProg *ebpf.Program
	for name, prog := range coll.Programs {
		fmt.Printf("  - Program: %s (Type: %s)\n", name, prog.Type())
		if prog.Type() == ebpf.XDP {
			xdpProg = prog
		}
	}

	if xdpProg == nil {
		fmt.Println("Error: No XDP program found in the object file")
		os.Exit(1)
	}

	// Attach XDP program to loopback interface
    iface, err := net.InterfaceByName("lo")
    if err != nil {
        fmt.Printf("Failed to find interface lo: %v\n", err)
        os.Exit(1)
    }

    l, err := link.AttachXDP(link.XDPOptions{
        Program:   xdpProg,
        Interface: iface.Index,
    })
    if err != nil {
        fmt.Printf("Failed to attach XDP program to lo: %v\n", err)
        os.Exit(1)
    }
    defer l.Close()


    fmt.Println("\nPress Ctrl+C to detach and exit...")

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)

    <-c

    fmt.Println("\n✓ Cleaning up and detaching...")
}
