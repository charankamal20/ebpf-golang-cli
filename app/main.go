// advanced-config.go
package main

import (
    "fmt"
    "os"
    "strconv"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/rlimit"
)

func updateExistingMap(port uint16) error {
    blockedPortMap, err := ebpf.LoadPinnedMap("/sys/fs/bpf/blocked_port_map", nil)
    if err != nil {
        return fmt.Errorf("failed to load pinned map: %v", err)
    }
    defer blockedPortMap.Close()

    key := uint32(0)
    if err := blockedPortMap.Update(key, port, ebpf.UpdateAny); err != nil {
        return fmt.Errorf("failed to update map: %v", err)
    }

    return nil
}

func loadProgramAndUpdatePort(port uint16) error {
    // Load the eBPF program from object file
    spec, err := ebpf.LoadCollectionSpec("xdp-drop.o")
    if err != nil {
        return fmt.Errorf("failed to load collection spec: %v", err)
    }

    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        return fmt.Errorf("failed to create collection: %v", err)
    }
    defer coll.Close()

    // Get the XDP program
    prog := coll.Programs["xdp"]
    if prog == nil {
        return fmt.Errorf("xdp_drop program not found")
    }

    // Get the map
    blockedPortMap := coll.Maps["blocked_port_map"]
    if blockedPortMap == nil {
        return fmt.Errorf("blocked_port_map not found")
    }

    // Update the port in the map
    key := uint32(0)
    if err := blockedPortMap.Update(key, port, ebpf.UpdateAny); err != nil {
        return fmt.Errorf("failed to update map: %v", err)
    }

    // Pin the map for future use
    if err := blockedPortMap.Pin("/sys/fs/bpf/blocked_port_map"); err != nil {
        fmt.Printf("Warning: failed to pin map: %v\n", err)
    }

    fmt.Println("✓ Loaded eBPF program and updated port")
    return nil
}

func sd() {
    if len(os.Args) != 2 {
        fmt.Printf("Usage: %s <port_number>\n", os.Args[0])
        fmt.Println("Example: ./advanced-config 8080")
        os.Exit(1)
    }

    // Parse port number
    port64, err := strconv.ParseUint(os.Args[1], 10, 16)
    if err != nil || port64 == 0 {
        fmt.Printf("Invalid port number: %s\n", os.Args[1])
        os.Exit(1)
    }
    port := uint16(port64)

    // Remove memory limit for eBPF
    if err := rlimit.RemoveMemlock(); err != nil {
        fmt.Printf("Failed to remove memlock: %v\n", err)
        os.Exit(1)
    }

    // Try to update existing map first
    if err := updateExistingMap(port); err != nil {
        fmt.Printf("Map not found, trying to load program: %v\n", err)

        // If that fails, try to load the program
        if err := loadProgramAndUpdatePort(port); err != nil {
            fmt.Printf("Failed to load program and update port: %v\n", err)
            fmt.Println("\nMake sure:")
            fmt.Println("1. xdp_drop.o exists in current directory, OR")
            fmt.Println("2. Your XDP program is already loaded with pinned map")
            fmt.Println("3. You're running as root/sudo")
            os.Exit(1)
        }
    } else {
        fmt.Printf("✓ Successfully updated existing map to block port %d\n", port)
    }
}
