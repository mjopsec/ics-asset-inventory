package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"ics-asset-inventory/internal/utils"
)

// ScanType represents the type of scan
type ScanType string

const (
	ScanTypeQuick  ScanType = "quick"
	ScanTypeFull   ScanType = "full"
	ScanTypeCustom ScanType = "custom"
)

// ScanMode represents the scanning mode
type ScanMode string

const (
	ScanModeActive  ScanMode = "active"   // Traditional active scanning
	ScanModePassive ScanMode = "passive"  // Passive monitoring only
	ScanModeHybrid  ScanMode = "hybrid"   // Both active and passive
)

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	StatusPending   ScanStatus = "pending"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// Scanner handles network scanning operations
type Scanner struct {
	logger         *utils.Logger
	config         *ScanConfig
	workerPool     chan struct{}
	results        chan *DeviceResult
	errors         chan error
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
	progress       *ScanProgress
	passiveScanner *PassiveScanner // NEW: passive scanner instance
}

// ScanConfig contains scanner configuration
type ScanConfig struct {
	IPRange        string
	ScanType       ScanType
	ScanMode       ScanMode           // NEW: active, passive, or hybrid
	Timeout        time.Duration
	MaxConcurrent  int
	Protocols      []string
	PortRanges     []PortRange
	EnablePassive  bool               // Enable passive monitoring
	PassiveConfig  *PassiveScanConfig // Passive scan configuration
	RetryAttempts  int
}

// PortRange represents a range of ports to scan
type PortRange struct {
	Start uint16
	End   uint16
}

// ScanProgress tracks scan progress
type ScanProgress struct {
	TotalHosts      int
	ScannedHosts    int
	DiscoveredHosts int
	TotalPorts      int
	ScannedPorts    int
	OpenPorts       int
	StartTime       time.Time
	ElapsedTime     time.Duration
	Status          ScanStatus
	Errors          []string
	mu              sync.Mutex
}

// DeviceResult represents a discovered device
type DeviceResult struct {
	IPAddress    string
	MACAddress   string
	Hostname     string
	OpenPorts    []PortInfo
	Protocol     string
	DeviceType   string
	Vendor       string
	Model        string
	Version      string
	ResponseTime time.Duration
	Timestamp    time.Time
	IsNew        bool
	Fingerprint  map[string]interface{}
}

// PortInfo contains information about an open port
type PortInfo struct {
	Port        uint16                 `json:"port"`
	Protocol    string                 `json:"protocol"`
	Service     string                 `json:"service"`
	Version     string                 `json:"version"`
	Banner      string                 `json:"banner"`
	IsSecure    bool                   `json:"is_secure"`
	Certificate *CertificateInfo       `json:"certificate,omitempty"`
}

// CertificateInfo contains SSL/TLS certificate information
type CertificateInfo struct {
	Subject      string
	Issuer       string
	ValidFrom    time.Time
	ValidTo      time.Time
	IsExpired    bool
	IsSelfSigned bool
}

// NewScanner creates a new network scanner with passive mode support
func NewScanner(config *ScanConfig, logger *utils.Logger) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	scanner := &Scanner{
		logger:     logger,
		config:     config,
		workerPool: make(chan struct{}, config.MaxConcurrent),
		results:    make(chan *DeviceResult, 100),
		errors:     make(chan error, 100),
		ctx:        ctx,
		cancel:     cancel,
		progress: &ScanProgress{
			Status:    StatusPending,
			StartTime: time.Now(),
			Errors:    make([]string, 0),
		},
	}
	
	// Initialize passive scanner if enabled
	if config.ScanMode == ScanModePassive || config.ScanMode == ScanModeHybrid {
		if config.PassiveConfig == nil {
			config.PassiveConfig = &PassiveScanConfig{
				Interface:   "eth0", // Default interface
				SnapLen:     65535,
				Promiscuous: true,
				Timeout:     30 * time.Second,
				BPFFilter:   buildBPFFilter(config.Protocols),
			}
		}
		
		passiveScanner, err := NewPassiveScanner(config.PassiveConfig, logger)
		if err != nil {
			logger.Error("Failed to create passive scanner", "error", err)
		} else {
			scanner.passiveScanner = passiveScanner
		}
	}
	
	return scanner
}

// Start begins the network scan with passive mode support
func (s *Scanner) Start() error {
	s.mu.Lock()
	if s.progress.Status == StatusRunning {
		s.mu.Unlock()
		return fmt.Errorf("scan already in progress")
	}
	s.progress.Status = StatusRunning
	s.progress.StartTime = time.Now()
	s.mu.Unlock()

	s.logger.Info("Starting network scan",
		"ipRange", s.config.IPRange,
		"scanType", s.config.ScanType,
		"scanMode", s.config.ScanMode,
		"protocols", s.config.Protocols)

	// Start passive scanner if enabled
	if s.passiveScanner != nil {
		if err := s.passiveScanner.Start(); err != nil {
			s.logger.Error("Failed to start passive scanner", "error", err)
			// Continue with active scanning if available
		} else {
			// Start passive result processor
			go s.processPassiveResults()
		}
	}

	// If passive-only mode, just monitor
	if s.config.ScanMode == ScanModePassive {
		s.logger.Info("Running in passive mode only - monitoring network traffic")
		
		// Start result processor for passive mode
		go s.processResults()
		go s.handleErrors()
		
		return nil
	}

	// Continue with active scanning for active or hybrid mode
	hosts, err := s.parseIPRange(s.config.IPRange)
	if err != nil {
		s.updateStatus(StatusFailed)
		return fmt.Errorf("failed to parse IP range: %w", err)
	}

	s.progress.TotalHosts = len(hosts)
	
	// Determine ports to scan
	ports := s.getPortsToScan()
	s.progress.TotalPorts = len(ports) * len(hosts)

	// Start result processor
	go s.processResults()

	// Start error handler
	go s.handleErrors()

	// Scan hosts
	for _, host := range hosts {
		select {
		case <-s.ctx.Done():
			s.updateStatus(StatusCancelled)
			return nil
		default:
			s.wg.Add(1)
			go s.scanHost(host, ports)
		}
	}

	// Wait for all scans to complete
	go func() {
		s.wg.Wait()
		
		// Wait a bit for passive scanner to catch more traffic
		if s.config.ScanMode == ScanModeHybrid {
			time.Sleep(10 * time.Second)
		}
		
		close(s.results)
		close(s.errors)
		
		if s.progress.Status == StatusRunning {
			s.updateStatus(StatusCompleted)
		}
	}()

	return nil
}

// Stop cancels the running scan
func (s *Scanner) Stop() {
	s.logger.Info("Stopping network scan")
	
	// Stop passive scanner if running
	if s.passiveScanner != nil {
		s.passiveScanner.Stop()
	}
	
	s.cancel()
	s.updateStatus(StatusCancelled)
}

// GetProgress returns current scan progress
func (s *Scanner) GetProgress() ScanProgress {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	
	progress := *s.progress
	progress.ElapsedTime = time.Since(progress.StartTime)
	
	// Add passive scan statistics if available
	if s.passiveScanner != nil && s.config.ScanMode != ScanModeActive {
		passiveHosts := s.passiveScanner.GetDiscoveredHosts()
		// Don't double count in hybrid mode
		if s.config.ScanMode == ScanModePassive {
			progress.DiscoveredHosts = len(passiveHosts)
		}
	}
	
	return progress
}

// GetResults returns the results channel
func (s *Scanner) GetResults() <-chan *DeviceResult {
	return s.results
}

// processPassiveResults processes results from passive scanner
func (s *Scanner) processPassiveResults() {
	if s.passiveScanner == nil {
		return
	}
	
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	discoveredIPs := make(map[string]bool)
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			hosts := s.passiveScanner.GetDiscoveredHosts()
			for ip, hostInfo := range hosts {
				// Check if this is a new discovery
				if !discoveredIPs[ip] {
					discoveredIPs[ip] = true
					
					// Convert passive host info to device result
					device := s.convertPassiveToDevice(hostInfo)
					
					s.logger.Info("New device discovered passively",
						"ip", ip,
						"protocols", hostInfo.Protocols,
						"deviceType", hostInfo.DeviceType)
					
					// Send to results channel
					select {
					case s.results <- device:
						s.updateProgress(func(p *ScanProgress) {
							p.DiscoveredHosts++
						})
					case <-s.ctx.Done():
						return
					}
				}
			}
		}
	}
}

// convertPassiveToDevice converts passive host info to device result
func (s *Scanner) convertPassiveToDevice(hostInfo *PassiveHostInfo) *DeviceResult {
	device := &DeviceResult{
		IPAddress:    hostInfo.IPAddress,
		MACAddress:   hostInfo.MACAddress,
		DeviceType:   hostInfo.DeviceType,
		Vendor:       hostInfo.Vendor,
		Timestamp:    time.Now(),
		IsNew:        true,
		Fingerprint:  hostInfo.Fingerprint,
		OpenPorts:    make([]PortInfo, 0),
	}
	
	// Set protocol based on detected protocols
	if len(hostInfo.Protocols) > 0 {
		device.Protocol = hostInfo.Protocols[0]
	}
	
	// Convert port activities to port info
	for _, activity := range hostInfo.OpenPorts {
		portInfo := PortInfo{
			Port:     activity.Port,
			Protocol: activity.Protocol,
			Service:  activity.Service,
			Banner:   activity.Banner,
		}
		device.OpenPorts = append(device.OpenPorts, portInfo)
	}
	
	// Add passive scan indicator
	device.Fingerprint["scan_method"] = "passive"
	device.Fingerprint["packet_count"] = hostInfo.PacketCount
	device.Fingerprint["auto_classified"] = true
	device.Fingerprint["classification_confidence"] = 85 // Example confidence
	
	return device
}

// GetPassiveStatistics returns passive scanning statistics
func (s *Scanner) GetPassiveStatistics() map[string]interface{} {
	if s.passiveScanner == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}
	
	stats := s.passiveScanner.GetStatistics()
	stats["enabled"] = true
	stats["mode"] = s.config.ScanMode
	
	return stats
}

// scanHost scans a single host (existing implementation)
func (s *Scanner) scanHost(host string, ports []uint16) {
	defer s.wg.Done()

	// Acquire worker slot
	select {
	case s.workerPool <- struct{}{}:
		defer func() { <-s.workerPool }()
	case <-s.ctx.Done():
		return
	}

	s.logger.Debug("Scanning host", "host", host)
	
	// Update progress
	s.updateProgress(func(p *ScanProgress) {
		p.ScannedHosts++
	})

	// Create device result
	device := &DeviceResult{
		IPAddress:   host,
		Timestamp:   time.Now(),
		IsNew:       true,
		Fingerprint: make(map[string]interface{}),
		OpenPorts:   make([]PortInfo, 0),
	}

	// Get MAC address
	device.MACAddress = s.getMACAddress(host)

	// Resolve hostname
	device.Hostname = s.resolveHostname(host)

	// Scan ports based on protocols
	foundDevice := false
	for _, protocol := range s.config.Protocols {
		ports := s.getProtocolPorts(protocol)
		for _, port := range ports {
			if portInfo := s.checkPort(host, port); portInfo != nil {
				device.OpenPorts = append(device.OpenPorts, *portInfo)
				foundDevice = true
				
				// Try to identify protocol
				if device.Protocol == "" {
					device.Protocol = s.identifyProtocolByPort(port)
				}
			}
		}
	}

	if foundDevice {
		// Update progress
		s.updateProgress(func(p *ScanProgress) {
			p.DiscoveredHosts++
			p.OpenPorts += len(device.OpenPorts)
		})

		// Identify device type based on ports
		s.identifyDevice(device)
		
		// Mark as auto-classified if identified
		if device.DeviceType != "Unknown Device" {
			device.Fingerprint["auto_classified"] = true
			device.Fingerprint["classification_confidence"] = 75
		}

		// Send result
		select {
		case s.results <- device:
		case <-s.ctx.Done():
			return
		}
	}
}

// Helper methods (keep all existing helper methods)
func (s *Scanner) getProtocolPorts(protocol string) []uint16 {
	protocolPorts := map[string][]uint16{
		"modbus":      {502},
		"dnp3":        {20000, 20547},
		"ethernet_ip": {44818, 2222},
		"bacnet":      {47808},
		"s7":          {102},
		"snmp":        {161, 162},
	}
	
	if ports, ok := protocolPorts[protocol]; ok {
		return ports
	}
	return []uint16{}
}

func (s *Scanner) checkPort(host string, port uint16) *PortInfo {
	address := fmt.Sprintf("%s:%d", host, port)
	
	// Try TCP connection
	conn, err := net.DialTimeout("tcp", address, s.config.Timeout)
	if err != nil {
		return nil
	}
	defer conn.Close()

	portInfo := &PortInfo{
		Port:     port,
		Protocol: "TCP",
		Service:  s.identifyService(port),
	}

	// Get banner
	portInfo.Banner = s.grabBanner(conn)

	// Check for SSL/TLS
	if s.isSSLPort(port) {
		portInfo.IsSecure = true
		portInfo.Certificate = s.getCertificateInfo(host, port)
	}

	return portInfo
}

func (s *Scanner) identifyDevice(device *DeviceResult) {
	// Try protocol detection for each open port
	for _, port := range device.OpenPorts {
		// Try protocol-specific detection based on port
		switch port.Port {
		case 502:
			device.Protocol = "Modbus TCP"
			device.DeviceType = "PLC"
			return
		case 102:
			device.Protocol = "Siemens S7"
			device.DeviceType = "PLC"
			device.Vendor = "Siemens"
			return
		case 20000, 20547:
			device.Protocol = "DNP3"
			device.DeviceType = "RTU"
			return
		case 44818, 2222:
			device.Protocol = "EtherNet/IP"
			device.DeviceType = "PLC"
			device.Vendor = "Rockwell/Allen-Bradley"
			return
		case 47808:
			device.Protocol = "BACnet"
			device.DeviceType = "Building Controller"
			return
		case 161, 162:
			device.Protocol = "SNMP"
			device.DeviceType = "Network Device"
			return
		}
	}

	// Generic identification based on open ports
	if device.DeviceType == "" {
		device.DeviceType = "Unknown Device"
	}
}

func (s *Scanner) identifyProtocolByPort(port uint16) string {
	protocols := map[uint16]string{
		102:   "Siemens S7",
		161:   "SNMP",
		162:   "SNMP",
		502:   "Modbus TCP",
		2222:  "EtherNet/IP",
		20000: "DNP3",
		20547: "DNP3",
		44818: "EtherNet/IP",
		47808: "BACnet",
	}
	
	if protocol, ok := protocols[port]; ok {
		return protocol
	}
	return ""
}

func (s *Scanner) parseIPRange(ipRange string) ([]string, error) {
	var hosts []string
	hostMap := make(map[string]bool) // To avoid duplicates

	// Split by comma for multiple entries
	entries := strings.Split(ipRange, ",")
	
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Check if it's a range (e.g., 192.168.1.1-192.168.1.10)
		if strings.Contains(entry, "-") {
			parts := strings.Split(entry, "-")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid range format: %s", entry)
			}
			
			startIP := net.ParseIP(strings.TrimSpace(parts[0]))
			endIP := net.ParseIP(strings.TrimSpace(parts[1]))
			
			if startIP == nil || endIP == nil {
				return nil, fmt.Errorf("invalid IP in range: %s", entry)
			}
			
			// Convert IPs to uint32 for comparison
			start := ipToUint32(startIP.To4())
			end := ipToUint32(endIP.To4())
			
			if start > end {
				return nil, fmt.Errorf("invalid range: start IP is greater than end IP")
			}
			
			// Generate all IPs in range
			for i := start; i <= end; i++ {
				ip := uint32ToIP(i).String()
				if !hostMap[ip] {
					hostMap[ip] = true
					hosts = append(hosts, ip)
				}
			}
			
		} else if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			// CIDR notation (e.g., 192.168.1.0/24)
			for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
				// Skip network and broadcast addresses for /24 and smaller
				ones, _ := ipNet.Mask.Size()
				if ones >= 24 && (ip[3] == 0 || ip[3] == 255) {
					continue
				}
				ipStr := ip.String()
				if !hostMap[ipStr] {
					hostMap[ipStr] = true
					hosts = append(hosts, ipStr)
				}
			}
			
		} else if ip := net.ParseIP(entry); ip != nil {
			// Single IP (e.g., 192.168.1.100)
			ipStr := ip.String()
			if !hostMap[ipStr] {
				hostMap[ipStr] = true
				hosts = append(hosts, ipStr)
			}
			
		} else {
			return nil, fmt.Errorf("invalid IP format: %s", entry)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("no valid hosts found in input")
	}

	s.logger.Info("Parsed IP range", "input", ipRange, "host_count", len(hosts))

	return hosts, nil
}

// Helper functions for IP range parsing
func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 4 {
		return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
	}
	return 0
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (s *Scanner) getPortsToScan() []uint16 {
	var ports []uint16
	
	switch s.config.ScanType {
	case ScanTypeQuick:
		// Common ICS/SCADA ports
		ports = []uint16{
			21, 22, 23, 80, 443,           // Common services
			102, 502, 1911, 2222, 2404,    // S7, Modbus
			20000, 20547,                   // DNP3
			44818, 2222,                    // EtherNet/IP
			47808,                          // BACnet
			161, 162,                       // SNMP
		}
	case ScanTypeFull:
		// Top 1000 ports for performance reasons
		ports = getTop1000Ports()
	case ScanTypeCustom:
		// Custom port ranges
		for _, r := range s.config.PortRanges {
			for p := r.Start; p <= r.End; p++ {
				ports = append(ports, p)
			}
		}
	}
	
	return ports
}

func getTop1000Ports() []uint16 {
	// Return common ports for now
	return []uint16{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3306, 3389, 5900, 8080, 8443, 102, 502, 1911, 2222, 2404,
		20000, 20547, 44818, 47808, 161, 162,
	}
}

func (s *Scanner) getMACAddress(ip string) string {
	// This would require ARP lookup
	// Simplified for now
	return ""
}

func (s *Scanner) resolveHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

func (s *Scanner) identifyService(port uint16) string {
	services := map[uint16]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		80:    "HTTP",
		443:   "HTTPS",
		102:   "S7",
		161:   "SNMP",
		502:   "Modbus",
		1911:  "Niagara Fox",
		2222:  "EtherNet/IP",
		2404:  "IEC-104",
		20000: "DNP3",
		44818: "EtherNet/IP",
		47808: "BACnet",
	}
	
	if service, ok := services[port]; ok {
		return service
	}
	return "Unknown"
}

func (s *Scanner) grabBanner(conn net.Conn) string {
	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}
	
	// Clean non-printable characters
	banner := string(buffer[:n])
	cleaned := ""
	for _, r := range banner {
		if r >= 32 && r < 127 {
			cleaned += string(r)
		}
	}
	
	return cleaned
}

func (s *Scanner) isSSLPort(port uint16) bool {
	sslPorts := []uint16{443, 8443, 465, 993, 995}
	for _, p := range sslPorts {
		if p == port {
			return true
		}
	}
	return false
}

func (s *Scanner) getCertificateInfo(host string, port uint16) *CertificateInfo {
	// TODO: Implement SSL/TLS certificate parsing
	return nil
}

// Progress and status updates
func (s *Scanner) updateProgress(fn func(*ScanProgress)) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	fn(s.progress)
}

func (s *Scanner) updateStatus(status ScanStatus) {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	s.progress.Status = status
	s.progress.ElapsedTime = time.Since(s.progress.StartTime)
}

func (s *Scanner) processResults() {
	// This would typically save results to database
	// For now, just log them
	for result := range s.results {
		s.logger.Info("Device discovered",
			"ip", result.IPAddress,
			"type", result.DeviceType,
			"protocol", result.Protocol,
			"ports", len(result.OpenPorts))
	}
}

func (s *Scanner) handleErrors() {
	for err := range s.errors {
		s.logger.Error("Scan error", "error", err)
		s.updateProgress(func(p *ScanProgress) {
			p.Errors = append(p.Errors, err.Error())
		})
	}
}

// buildBPFFilter builds a BPF filter for industrial protocols
func buildBPFFilter(protocols []string) string {
	var filters []string
	
	portMap := map[string][]string{
		"modbus":      {"502"},
		"dnp3":        {"20000", "20547"},
		"ethernet_ip": {"44818", "2222"},
		"bacnet":      {"47808"},
		"s7":          {"102"},
		"snmp":        {"161", "162"},
	}
	
	for _, protocol := range protocols {
		if ports, ok := portMap[protocol]; ok {
			for _, port := range ports {
				filters = append(filters, fmt.Sprintf("port %s", port))
			}
		}
	}
	
	if len(filters) == 0 {
		// Default filter for all industrial protocols
		return "port 102 or port 502 or port 20000 or port 44818 or port 47808 or port 161"
	}
	
	return strings.Join(filters, " or ")
}
