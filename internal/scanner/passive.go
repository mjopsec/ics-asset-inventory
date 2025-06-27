package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ics-asset-inventory/internal/utils"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// PassiveScanner implements passive network monitoring
type PassiveScanner struct {
	config          *PassiveScanConfig
	handle          *pcap.Handle
	packetSource    *gopacket.PacketSource
	discoveredHosts map[string]*PassiveHostInfo
	mu              sync.RWMutex
	ctx             context.Context
	cancel          context.CancelFunc
	logger          *utils.Logger
}

// PassiveScanConfig contains passive scanner configuration
type PassiveScanConfig struct {
	Interface      string
	SnapLen        int32
	Promiscuous    bool
	Timeout        time.Duration
	BPFFilter      string
	ProtocolPorts  map[string][]uint16
}

// PassiveHostInfo contains information gathered passively
type PassiveHostInfo struct {
	IPAddress      string
	MACAddress     string
	FirstSeen      time.Time
	LastSeen       time.Time
	OpenPorts      map[uint16]*PortActivity
	Protocols      []string
	DeviceType     string
	Vendor         string
	Fingerprint    map[string]interface{}
	PacketCount    int64
	BytesReceived  int64
	BytesSent      int64
}

// PortActivity tracks port usage
type PortActivity struct {
	Port         uint16
	Protocol     string
	Service      string
	FirstSeen    time.Time
	LastSeen     time.Time
	PacketCount  int64
	Banner       string
}

// NewPassiveScanner creates a new passive scanner
func NewPassiveScanner(config *PassiveScanConfig, logger *utils.Logger) (*PassiveScanner, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &PassiveScanner{
		config:          config,
		discoveredHosts: make(map[string]*PassiveHostInfo),
		ctx:            ctx,
		cancel:         cancel,
		logger:         logger,
	}, nil
}

// Start begins passive monitoring
func (ps *PassiveScanner) Start() error {
	// Open device for packet capture
	handle, err := pcap.OpenLive(
		ps.config.Interface,
		ps.config.SnapLen,
		ps.config.Promiscuous,
		ps.config.Timeout,
	)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", ps.config.Interface, err)
	}
	ps.handle = handle

	// Set BPF filter to capture only industrial protocol traffic
	if ps.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(ps.config.BPFFilter); err != nil {
			return fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	// Create packet source
	ps.packetSource = gopacket.NewPacketSource(handle, handle.LinkType())

	// Start packet processing
	go ps.processPackets()

	ps.logger.Info("Passive scanning started",
		"interface", ps.config.Interface,
		"filter", ps.config.BPFFilter)

	return nil
}

// Stop stops passive monitoring
func (ps *PassiveScanner) Stop() {
	ps.cancel()
	if ps.handle != nil {
		ps.handle.Close()
	}
	ps.logger.Info("Passive scanning stopped")
}

// processPackets processes captured packets
func (ps *PassiveScanner) processPackets() {
	for {
		select {
		case <-ps.ctx.Done():
			return
		case packet := <-ps.packetSource.Packets():
			ps.analyzePacket(packet)
		}
	}
}

// analyzePacket analyzes a single packet
func (ps *PassiveScanner) analyzePacket(packet gopacket.Packet) {
	// Extract network layer
	networkLayer := packet.NetworkLayer()
	if networkLayer == nil {
		return
	}

	// Get source and destination IPs
	var srcIP, dstIP string
	if ipv4, ok := networkLayer.(*layers.IPv4); ok {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6, ok := networkLayer.(*layers.IPv6); ok {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	} else {
		return
	}

	// Extract transport layer
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return
	}

	// Get port information
	var srcPort, dstPort uint16
	var protocol string
	
	switch transport := transportLayer.(type) {
	case *layers.TCP:
		srcPort = uint16(transport.SrcPort)
		dstPort = uint16(transport.DstPort)
		protocol = "TCP"
	case *layers.UDP:
		srcPort = uint16(transport.SrcPort)
		dstPort = uint16(transport.DstPort)
		protocol = "UDP"
	default:
		return
	}

	// Check if this is an industrial protocol port
	if ps.isIndustrialPort(srcPort) || ps.isIndustrialPort(dstPort) {
		// Update host information
		ps.updateHostInfo(srcIP, srcPort, dstIP, dstPort, protocol, packet)
		
		// Analyze application layer for protocol detection
		ps.analyzeApplicationLayer(packet, srcIP, dstIP, srcPort, dstPort)
	}
}

// analyzeApplicationLayer performs deep packet inspection
func (ps *PassiveScanner) analyzeApplicationLayer(packet gopacket.Packet, srcIP, dstIP string, srcPort, dstPort uint16) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}

	payload := applicationLayer.Payload()
	if len(payload) == 0 {
		return
	}

	// Detect Modbus TCP
	if (srcPort == 502 || dstPort == 502) && len(payload) >= 8 {
		if ps.isModbusTCP(payload) {
			ps.updateProtocolInfo(srcIP, dstIP, "Modbus TCP", "PLC")
		}
	}

	// Detect DNP3
	if (srcPort == 20000 || dstPort == 20000) && len(payload) >= 10 {
		if ps.isDNP3(payload) {
			ps.updateProtocolInfo(srcIP, dstIP, "DNP3", "RTU/Outstation")
		}
	}

	// Detect EtherNet/IP
	if (srcPort == 44818 || dstPort == 44818) && len(payload) >= 24 {
		if ps.isEtherNetIP(payload) {
			ps.updateProtocolInfo(srcIP, dstIP, "EtherNet/IP", "PLC")
		}
	}

	// Detect S7
	if (srcPort == 102 || dstPort == 102) && len(payload) >= 7 {
		if ps.isS7(payload) {
			ps.updateProtocolInfo(srcIP, dstIP, "Siemens S7", "PLC")
		}
	}
}

// Protocol detection methods
func (ps *PassiveScanner) isModbusTCP(payload []byte) bool {
	// Modbus TCP header check
	if len(payload) < 8 {
		return false
	}
	// Check protocol ID (should be 0x0000 for Modbus)
	return payload[2] == 0x00 && payload[3] == 0x00
}

func (ps *PassiveScanner) isDNP3(payload []byte) bool {
	// DNP3 start bytes check
	if len(payload) < 2 {
		return false
	}
	return payload[0] == 0x05 && payload[1] == 0x64
}

func (ps *PassiveScanner) isEtherNetIP(payload []byte) bool {
	// EtherNet/IP encapsulation header check
	if len(payload) < 4 {
		return false
	}
	// Check for common EtherNet/IP commands
	cmd := uint16(payload[0]) | uint16(payload[1])<<8
	return cmd == 0x0065 || cmd == 0x0063 || cmd == 0x006F
}

func (ps *PassiveScanner) isS7(payload []byte) bool {
	// S7 TPKT header check
	if len(payload) < 4 {
		return false
	}
	return payload[0] == 0x03 && payload[1] == 0x00
}

// updateHostInfo updates discovered host information
func (ps *PassiveScanner) updateHostInfo(srcIP string, srcPort uint16, dstIP string, dstPort uint16, protocol string, packet gopacket.Packet) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Update source host
	if ps.isLocalIP(srcIP) {
		host := ps.getOrCreateHost(srcIP)
		host.LastSeen = time.Now()
		host.PacketCount++
		host.BytesSent += int64(len(packet.Data()))
		
		// Extract MAC address
		if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
			if eth, ok := ethernetLayer.(*layers.Ethernet); ok {
				host.MACAddress = eth.SrcMAC.String()
			}
		}
		
		// Update port activity for industrial ports
		if ps.isIndustrialPort(srcPort) {
			ps.updatePortActivity(host, srcPort, protocol, "source")
		}
	}

	// Update destination host
	if ps.isLocalIP(dstIP) {
		host := ps.getOrCreateHost(dstIP)
		host.LastSeen = time.Now()
		host.PacketCount++
		host.BytesReceived += int64(len(packet.Data()))
		
		// Extract MAC address
		if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
			if eth, ok := ethernetLayer.(*layers.Ethernet); ok {
				host.MACAddress = eth.DstMAC.String()
			}
		}
		
		// Update port activity for industrial ports
		if ps.isIndustrialPort(dstPort) {
			ps.updatePortActivity(host, dstPort, protocol, "destination")
		}
	}
}

// updateProtocolInfo updates protocol-specific information
func (ps *PassiveScanner) updateProtocolInfo(srcIP, dstIP, protocol, deviceType string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Update source host if local
	if ps.isLocalIP(srcIP) {
		host := ps.getOrCreateHost(srcIP)
		if !containsString(host.Protocols, protocol) {
			host.Protocols = append(host.Protocols, protocol)
		}
		if host.DeviceType == "" {
			host.DeviceType = deviceType
		}
	}

	// Update destination host if local
	if ps.isLocalIP(dstIP) {
		host := ps.getOrCreateHost(dstIP)
		if !containsString(host.Protocols, protocol) {
			host.Protocols = append(host.Protocols, protocol)
		}
		if host.DeviceType == "" {
			host.DeviceType = deviceType
		}
	}
}

// getOrCreateHost gets or creates a host entry
func (ps *PassiveScanner) getOrCreateHost(ip string) *PassiveHostInfo {
	if host, exists := ps.discoveredHosts[ip]; exists {
		return host
	}

	host := &PassiveHostInfo{
		IPAddress:   ip,
		FirstSeen:   time.Now(),
		LastSeen:    time.Now(),
		OpenPorts:   make(map[uint16]*PortActivity),
		Protocols:   []string{},
		Fingerprint: make(map[string]interface{}),
	}
	ps.discoveredHosts[ip] = host
	
	// Log new host discovery
	ps.logger.Info("New host discovered passively",
		"ip", ip,
		"timestamp", host.FirstSeen)
	
	return host
}

// updatePortActivity updates port activity information
func (ps *PassiveScanner) updatePortActivity(host *PassiveHostInfo, port uint16, protocol, direction string) {
	activity, exists := host.OpenPorts[port]
	if !exists {
		activity = &PortActivity{
			Port:      port,
			Protocol:  protocol,
			Service:   ps.identifyService(port),
			FirstSeen: time.Now(),
		}
		host.OpenPorts[port] = activity
	}
	
	activity.LastSeen = time.Now()
	activity.PacketCount++
}

// isIndustrialPort checks if a port is an industrial protocol port
func (ps *PassiveScanner) isIndustrialPort(port uint16) bool {
	industrialPorts := []uint16{
		102,   // S7
		502,   // Modbus
		1911,  // Niagara Fox
		2222,  // EtherNet/IP Alt
		2404,  // IEC-104
		20000, // DNP3
		20547, // DNP3 Alt
		44818, // EtherNet/IP
		47808, // BACnet
		161,   // SNMP
		162,   // SNMP Trap
	}
	
	for _, p := range industrialPorts {
		if port == p {
			return true
		}
	}
	return false
}

// identifyService identifies service by port
func (ps *PassiveScanner) identifyService(port uint16) string {
	services := map[uint16]string{
		102:   "S7",
		502:   "Modbus",
		1911:  "Niagara Fox",
		2222:  "EtherNet/IP",
		2404:  "IEC-104",
		20000: "DNP3",
		44818: "EtherNet/IP",
		47808: "BACnet",
		161:   "SNMP",
	}
	
	if service, ok := services[port]; ok {
		return service
	}
	return fmt.Sprintf("Port %d", port)
}

// isLocalIP checks if an IP is in the local network range
func (ps *PassiveScanner) isLocalIP(ip string) bool {
	// Simple check for private IP ranges
	// In production, this should be configurable
	return true // For now, capture all IPs
}

// GetDiscoveredHosts returns discovered hosts
func (ps *PassiveScanner) GetDiscoveredHosts() map[string]*PassiveHostInfo {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	hosts := make(map[string]*PassiveHostInfo)
	for k, v := range ps.discoveredHosts {
		hosts[k] = v
	}
	return hosts
}

// GetStatistics returns passive scanning statistics
func (ps *PassiveScanner) GetStatistics() map[string]interface{} {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	
	stats := map[string]interface{}{
		"hosts_discovered": len(ps.discoveredHosts),
		"total_packets":    ps.getTotalPackets(),
		"protocols_detected": ps.getDetectedProtocols(),
		"uptime":          time.Since(ps.getStartTime()),
	}
	
	return stats
}

// Helper functions
func (ps *PassiveScanner) getTotalPackets() int64 {
	var total int64
	for _, host := range ps.discoveredHosts {
		total += host.PacketCount
	}
	return total
}

func (ps *PassiveScanner) getDetectedProtocols() []string {
	protocols := make(map[string]bool)
	for _, host := range ps.discoveredHosts {
		for _, p := range host.Protocols {
			protocols[p] = true
		}
	}
	
	var result []string
	for p := range protocols {
		result = append(result, p)
	}
	return result
}

func (ps *PassiveScanner) getStartTime() time.Time {
	var earliest time.Time
	for _, host := range ps.discoveredHosts {
		if earliest.IsZero() || host.FirstSeen.Before(earliest) {
			earliest = host.FirstSeen
		}
	}
	return earliest
}

// containsString checks if a slice contains a string
func containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}