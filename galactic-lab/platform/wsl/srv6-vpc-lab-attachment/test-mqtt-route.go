// =============================================================================
// Test MQTT Route Injection for Galactic Agent
// =============================================================================
// Author: Sajjad Ahmed
// Company: Multi Naturals Inc.
// Created: January 2026
//
// PURPOSE:
// This script creates a properly encoded protobuf message and publishes it
// to the local MQTT broker. The galactic-agent will receive this message
// and program the route into the WSL2 Linux kernel.
//
// USAGE:
//   cd ~/datum/galantic-vpc
//   go run test-mqtt-route.go
//
// PREREQUISITES:
//   - Mosquitto MQTT broker running: sudo systemctl start mosquitto
//   - galactic-agent running: sudo ./galactic-agent/galactic-agent --config galactic-agent-config.yaml
//
// HOW IT WORKS:
// The galactic-agent expects protobuf-encoded messages. This script manually
// encodes the protobuf binary format based on the remote.proto definitions.
//
// Protobuf wire format:
//   - Field 1 (network): tag=0x0a, length-delimited string
//   - Field 2 (srv6_endpoint): tag=0x12, length-delimited string
//   - Field 3 (srv6_segments): tag=0x1a, length-delimited string (repeated)
//   - Field 4 (status): tag=0x20, varint (0=ADD, 1=DELETE)
//
// Envelope wraps Route in field 3: tag=0x1a
//
// =============================================================================

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// encodeString creates a protobuf length-delimited string field
func encodeString(fieldNum int, value string) []byte {
	tag := byte((fieldNum << 3) | 2) // wire type 2 = length-delimited
	length := byte(len(value))
	result := []byte{tag, length}
	result = append(result, []byte(value)...)
	return result
}

// encodeVarint creates a protobuf varint field
func encodeVarint(fieldNum int, value int) []byte {
	tag := byte((fieldNum << 3) | 0) // wire type 0 = varint
	return []byte{tag, byte(value)}
}

// encodeRoute creates a protobuf-encoded Route message
func encodeRoute(network, srv6Endpoint string, srv6Segments []string, status int) []byte {
	var route []byte

	// Field 1: network (string)
	route = append(route, encodeString(1, network)...)

	// Field 2: srv6_endpoint (string)
	route = append(route, encodeString(2, srv6Endpoint)...)

	// Field 3: srv6_segments (repeated string)
	for _, seg := range srv6Segments {
		route = append(route, encodeString(3, seg)...)
	}

	// Field 4: status (enum/varint, 0=ADD, 1=DELETE)
	route = append(route, encodeVarint(4, status)...)

	return route
}

// generateSRv6Endpoint creates a properly formatted SRv6 endpoint
// The galactic-agent expects VPC ID (48 bits) and VPCAttachment ID (16 bits)
// encoded in the lower 64 bits of the IPv6 address.
//
// Format: fc00:XXXX:XXXX:XXXX:VVVV:VVVV:VVVV:AAAA
//   - fc00::/16 = SRv6 prefix
//   - VVVV:VVVV:VVVV = VPC ID (48 bits, hex)
//   - AAAA = VPCAttachment ID (16 bits, hex)
//
// Example: fc00::0001:0000:0000:0001 = VPC=000000000001, VPCAttachment=0001
func generateSRv6Endpoint(vpcHex string, vpcAttachmentHex string) string {
	// Pad VPC to 12 hex chars (48 bits)
	for len(vpcHex) < 12 {
		vpcHex = "0" + vpcHex
	}
	// Pad VPCAttachment to 4 hex chars (16 bits)
	for len(vpcAttachmentHex) < 4 {
		vpcAttachmentHex = "0" + vpcAttachmentHex
	}
	
	// Build IPv6: fc00:0000:0000:0000:VVVV:VVVV:VVVV:AAAA
	// VPC goes in bytes 8-13, VPCAttachment in bytes 14-15
	return fmt.Sprintf("fc00::%s:%s:%s:%s",
		vpcHex[0:4], vpcHex[4:8], vpcHex[8:12], vpcAttachmentHex)
}

// encodeEnvelope wraps a Route in an Envelope (field 3)
func encodeEnvelope(route []byte) []byte {
	// Envelope field 3 = Route
	tag := byte((3 << 3) | 2) // field 3, wire type 2 (length-delimited)
	length := byte(len(route))
	result := []byte{tag, length}
	result = append(result, route...)
	return result
}

// createVRF creates a VRF interface for the given VPC and attachment
// VRF = Virtual Routing and Forwarding - provides network isolation (Private Cloud)
// Each VPC gets its own VRF with isolated routing table
func createVRF(vpcHex, attachmentHex string, tableID int) (string, error) {
	// The agent expects VRF interface name format: G{vpc_base62}{attachment_base62}V
	// For simplicity, we use the hex values directly (agent converts hex to base62)
	// But the lookup uses: first 9 chars of vpc + first 3 chars of attachment + "V"
	vrfName := fmt.Sprintf("G%09s%03sV", vpcHex[len(vpcHex)-9:], attachmentHex[len(attachmentHex)-3:])
	
	fmt.Printf("\n🔧 Creating VRF: %s (table %d)\n", vrfName, tableID)
	
	// Check if VRF already exists
	checkCmd := exec.Command("ip", "link", "show", vrfName)
	if err := checkCmd.Run(); err == nil {
		fmt.Printf("   ✅ VRF %s already exists\n", vrfName)
		return vrfName, nil
	}
	
	// Create VRF interface
	// sudo ip link add <name> type vrf table <id>
	createCmd := exec.Command("sudo", "ip", "link", "add", vrfName, "type", "vrf", "table", fmt.Sprintf("%d", tableID))
	if output, err := createCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to create VRF: %v, output: %s", err, output)
	}
	
	// Bring VRF interface up
	upCmd := exec.Command("sudo", "ip", "link", "set", vrfName, "up")
	if output, err := upCmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("failed to bring up VRF: %v, output: %s", err, output)
	}
	
	fmt.Printf("   ✅ VRF %s created successfully\n", vrfName)
	return vrfName, nil
}

func main() {
	fmt.Println("=" + strings.Repeat("=", 69))
	fmt.Println(" Galactic Agent MQTT Route Injection Test")
	fmt.Println(" Author: Sajjad Ahmed, Multi Naturals Inc.")
	fmt.Println("=" + strings.Repeat("=", 69))

	// ==========================================================================
	// WHAT IS A VRF? (Virtual Routing and Forwarding)
	// ==========================================================================
	// A VRF is like a "virtual router" inside Linux. Each VRF has:
	//   - Its own routing table (isolated from other VRFs)
	//   - Its own interfaces
	//   - Its own route policies
	//
	// PRIVATE CLOUD = VPC = VRF
	// When we say "Private Cloud", we mean your traffic is isolated from others.
	// Each customer/tenant gets their own VRF with their own routing table.
	//
	// In Datum's architecture:
	//   - VPC ID identifies the customer's virtual private cloud
	//   - VPCAttachment ID identifies a specific attachment point (POP location)
	//   - Together they create a unique VRF: G{vpc}{attachment}V
	// ==========================================================================

	// ==========================================================================
	// SRv6 Endpoint Format for galactic-agent
	// ==========================================================================
	// The agent expects VPC ID (48 bits) and VPCAttachment ID (16 bits) encoded
	// in the lower 64 bits of the IPv6 address:
	//   fc00:0000:0000:0000:VVVV:VVVV:VVVV:AAAA
	//
	// We use:
	//   VPC ID = "000000000001" (hex) = test VPC
	//   VPCAttachment ID = "0001" (hex) for AMS, "0002" for IAD
	// ==========================================================================

	vpcID := "000000000001"  // Test VPC ID (48 bits hex)
	amsAttachment := "0001"  // AMS VPCAttachment ID
	iadAttachment := "0002"  // IAD VPCAttachment ID

	amsEndpoint := generateSRv6Endpoint(vpcID, amsAttachment)
	iadEndpoint := generateSRv6Endpoint(vpcID, iadAttachment)

	fmt.Printf("\n📋 SRv6 Endpoint Encoding:\n")
	fmt.Printf("   VPC ID:            %s\n", vpcID)
	fmt.Printf("   AMS Attachment:    %s → %s\n", amsAttachment, amsEndpoint)
	fmt.Printf("   IAD Attachment:    %s → %s\n", iadAttachment, iadEndpoint)

	// ==========================================================================
	// STEP 0: Create VRF interfaces (simulates CNI registration)
	// ==========================================================================
	// In production, the CNI plugin creates these VRFs when pods are scheduled.
	// For testing, we create them manually to simulate a "Private Cloud" setup.
	// ==========================================================================
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🏗️  STEP 0: Creating VRF interfaces (Private Cloud setup)")
	fmt.Println(strings.Repeat("=", 70))
	
	amsVRF, err := createVRF(vpcID, amsAttachment, 100)
	if err != nil {
		fmt.Printf("   ⚠️  Warning: %v\n", err)
		fmt.Println("   Run with sudo or create VRF manually:")
		fmt.Printf("   sudo ip link add G%09s%03sV type vrf table 100\n", vpcID[len(vpcID)-9:], amsAttachment[len(amsAttachment)-3:])
	}
	
	iadVRF, err := createVRF(vpcID, iadAttachment, 101)
	if err != nil {
		fmt.Printf("   ⚠️  Warning: %v\n", err)
	}
	
	_ = amsVRF
	_ = iadVRF

	// ==========================================================================
	// TEST 1: Add route to AMS (192.168.2.0/24)
	// ==========================================================================
	route1 := encodeRoute(
		"192.168.2.0/24",       // network
		amsEndpoint,            // srv6_endpoint (AMS with proper encoding)
		[]string{amsEndpoint},  // srv6_segments
		0,                      // status: ADD
	)
	envelope1 := encodeEnvelope(route1)

	fmt.Println("\n📤 TEST 1: Add route to AMS")
	fmt.Printf("   Network:       192.168.2.0/24\n")
	fmt.Printf("   SRv6 Endpoint: %s\n", amsEndpoint)
	fmt.Printf("   Segments:      [%s]\n", amsEndpoint)
	fmt.Printf("   Status:        ADD (0)\n")
	fmt.Printf("   Binary (hex):  %s\n", hex.EncodeToString(envelope1))
	fmt.Printf("   Binary size:   %d bytes\n", len(envelope1))

	// Save to file and publish via mosquitto_pub
	publishToMQTT("galactic/routes/wsl", envelope1, "route_ams.bin")

	// ==========================================================================
	// TEST 2: Add route to IAD (192.168.3.0/24)
	// ==========================================================================
	route2 := encodeRoute(
		"192.168.3.0/24",       // network
		iadEndpoint,            // srv6_endpoint (IAD with proper encoding)
		[]string{iadEndpoint},  // srv6_segments
		0,                      // status: ADD
	)
	envelope2 := encodeEnvelope(route2)

	fmt.Println("\n📤 TEST 2: Add route to IAD")
	fmt.Printf("   Network:       192.168.3.0/24\n")
	fmt.Printf("   SRv6 Endpoint: %s\n", iadEndpoint)
	fmt.Printf("   Segments:      [%s]\n", iadEndpoint)
	fmt.Printf("   Status:        ADD (0)\n")
	fmt.Printf("   Binary (hex):  %s\n", hex.EncodeToString(envelope2))

	publishToMQTT("galactic/routes/wsl", envelope2, "route_iad.bin")

	// ==========================================================================
	// Verification commands
	// ==========================================================================
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("🔍 VERIFICATION: Run these commands to check if routes were added:")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("")
	fmt.Println("   # Check VRF interfaces were created:")
	fmt.Println("   ip link show type vrf")
	fmt.Println("")
	fmt.Println("   # Check routes in VRF tables (100 for AMS, 101 for IAD):")
	fmt.Println("   ip -6 route show table 100")
	fmt.Println("   ip -6 route show table 101")
	fmt.Println("")
	fmt.Println("   # Check all SRv6 encapsulated routes:")
	fmt.Println("   ip -6 route show table all | grep 'encap seg6'")
	fmt.Println("")
	fmt.Println("   # Check main routing table:")
	fmt.Println("   ip -6 route show | grep -E '192.168.2|192.168.3'")
	fmt.Println(strings.Repeat("=", 70))
}

// publishToMQTT saves binary to file and publishes via mosquitto_pub
func publishToMQTT(topic string, data []byte, filename string) {
	// Write binary to /tmp with world-writable permissions
	tmpFile := "/tmp/" + filename
	
	// Write binary data directly to file (0777 for any user to read/write)
	err := os.WriteFile(tmpFile, data, 0777)
	if err != nil {
		fmt.Printf("   ❌ Failed to create binary file: %v\n", err)
		// Provide manual command as fallback
		hexStr := ""
		for _, b := range data {
			hexStr += fmt.Sprintf("\\x%02x", b)
		}
		fmt.Printf("   Manual command: printf '%s' > %s\n", hexStr, tmpFile)
		return
	}

	// Publish using mosquitto_pub with file input
	cmd := exec.Command("mosquitto_pub", "-h", "localhost", "-t", topic, "-f", tmpFile)
	err = cmd.Run()
	if err != nil {
		fmt.Printf("   ❌ Failed to publish: %v\n", err)
		fmt.Printf("   Manual command: mosquitto_pub -h localhost -t %s -f %s\n", topic, tmpFile)
		return
	}

	fmt.Printf("   ✅ Published to topic: %s\n", topic)
}
