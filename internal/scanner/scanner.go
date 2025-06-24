package scanner

import (
	"context"
	"fmt"
	"net"
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
	logger      *utils.Logger
	config      *ScanConfig
	workerPool  chan struct{}
	results     chan *DeviceResult
	errors      chan error
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	progress    *ScanProgress
}

// ScanConfig contains scanner configuration
type ScanConfig struct {
	IPRange        string
	ScanType       ScanType
	Timeout        time.Duration
	MaxConcurrent  int
	Protocols      []string
	PortRanges     []PortRange
	EnablePassive  bool
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
	Port        uint16
	Protocol    string
	Service     string
	Version     string
	Banner      string
	IsSecure    bool
	Certificate *CertificateInfo
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

// NewScanner creates a new network scanner
func NewScanner(config *ScanConfig, logger *utils.Logger) *Scanner {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Scanner{
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
}

// Start begins the network scan
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
		"protocols", s.config.Protocols)

	// Parse IP range
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
	s.cancel()
	s.updateStatus(StatusCancelled)
}

// GetProgress returns current scan progress
func (s *Scanner) GetProgress() ScanProgress {
	s.progress.mu.Lock()
	defer s.progress.mu.Unlock()
	
	progress := *s.progress
	progress.ElapsedTime = time.Since(progress.StartTime)
	return progress
}

// GetResults returns the results channel
func (s *Scanner) GetResults() <-chan *DeviceResult {
	return s.results
}

// scanHost scans a single host
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

	// Check if host is alive
	if !s.isHostAlive(host) {
		s.logger.Debug("Host not responding", "host", host)
		return
	}

	// Create device result
	device := &DeviceResult{
		IPAddress:   host,
		Timestamp:   time.Now(),
		IsNew:       true,
		Fingerprint: make(map[string]interface{}),
	}

	// Get MAC address
	device.MACAddress = s.getMACAddress(host)

	// Resolve hostname
	device.Hostname = s.resolveHostname(host)

	// Scan ports
	openPorts := s.scanPorts(host, ports)
	device.OpenPorts = openPorts

	if len(openPorts) > 0 {
		// Update progress
		s.updateProgress(func(p *ScanProgress) {
			p.DiscoveredHosts++
			p.OpenPorts += len(openPorts)
		})

		// Identify device
		s.identifyDevice(device)

		// Send result
		select {
		case s.results <- device:
		case <-s.ctx.Done():
			return
		}
	}
}

// scanPorts scans ports on a host
func (s *Scanner) scanPorts(host string, ports []uint16) []PortInfo {
	var openPorts []PortInfo
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range ports {
		// Check context
		select {
		case <-s.ctx.Done():
			return openPorts
		default:
		}

		wg.Add(1)
		go func(p uint16) {
			defer wg.Done()

			// Update progress
			s.updateProgress(func(prog *ScanProgress) {
				prog.ScannedPorts++
			})

			if portInfo := s.checkPort(host, p); portInfo != nil {
				mu.Lock()
				openPorts = append(openPorts, *portInfo)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// checkPort checks if a port is open
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

// identifyDevice identifies device type and details
func (s *Scanner) identifyDevice(device *DeviceResult) {
	// Try protocol detection for each open port
	for _, port := range device.OpenPorts {
		// Try protocol-specific detection based on port
		switch port.Port {
		case 502:
			if s.detectModbus(device, port.Port) {
				return
			}
		case 102:
			if s.detectS7(device, port.Port) {
				return
			}
		case 20000, 20547:
			if s.detectDNP3(device, port.Port) {
				return
			}
		case 44818, 2222:
			if s.detectEtherNetIP(device, port.Port) {
				return
			}
		case 47808:
			if s.detectBACnet(device, port.Port) {
				return
			}
		case 161, 162:
			if s.detectSNMP(device, port.Port) {
				return
			}
		}
	}

	// Generic identification based on open ports
	s.identifyByPorts(device)
}

// Protocol detection methods (simplified for now)
func (s *Scanner) detectModbus(device *DeviceResult, port uint16) bool {
	// In a real implementation, this would use the protocol detector
	if port == 502 {
		device.Protocol = "Modbus TCP"
		device.DeviceType = "PLC"
		device.Vendor = "Generic Modbus"
		return true
	}
	return false
}

func (s *Scanner) detectS7(device *DeviceResult, port uint16) bool {
	if port == 102 {
		device.Protocol = "Siemens S7"
		device.DeviceType = "PLC"
		device.Vendor = "Siemens"
		return true
	}
	return false
}

func (s *Scanner) detectDNP3(device *DeviceResult, port uint16) bool {
	if port == 20000 || port == 20547 {
		device.Protocol = "DNP3"
		device.DeviceType = "RTU"
		return true
	}
	return false
}

func (s *Scanner) detectEtherNetIP(device *DeviceResult, port uint16) bool {
	if port == 44818 || port == 2222 {
		device.Protocol = "EtherNet/IP"
		device.DeviceType = "PLC"
		device.Vendor = "Rockwell/Allen-Bradley"
		return true
	}
	return false
}

func (s *Scanner) detectBACnet(device *DeviceResult, port uint16) bool {
	if port == 47808 {
		device.Protocol = "BACnet"
		device.DeviceType = "Building Controller"
		return true
	}
	return false
}

func (s *Scanner) detectSNMP(device *DeviceResult, port uint16) bool {
	if port == 161 || port == 162 {
		device.Protocol = "SNMP"
		device.DeviceType = "Network Device"
		return true
	}
	return false
}

// Helper methods

func (s *Scanner) parseIPRange(ipRange string) ([]string, error) {
	var hosts []string

	// Check if it's a CIDR notation
	if _, ipNet, err := net.ParseCIDR(ipRange); err == nil {
		for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
			// Skip network and broadcast addresses
			if ip[3] != 0 && ip[3] != 255 {
				hosts = append(hosts, ip.String())
			}
		}
	} else if ip := net.ParseIP(ipRange); ip != nil {
		// Single IP
		hosts = append(hosts, ip.String())
	} else {
		return nil, fmt.Errorf("invalid IP range format: %s", ipRange)
	}

	return hosts, nil
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

func (s *Scanner) isHostAlive(host string) bool {
	// Try ICMP ping first (requires privileges)
	// For now, we'll use a simple TCP check on common ports
	commonPorts := []uint16{80, 443, 22, 445, 139, 502, 102}
	
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	
	return false
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

func (s *Scanner) identifyByPorts(device *DeviceResult) {
	// Basic identification based on open ports
	for _, port := range device.OpenPorts {
		switch port.Port {
		case 502:
			device.DeviceType = "PLC"
			device.Protocol = "Modbus"
		case 102:
			device.DeviceType = "PLC"
			device.Protocol = "S7"
			device.Vendor = "Siemens"
		case 44818:
			device.DeviceType = "PLC"
			device.Protocol = "EtherNet/IP"
		case 47808:
			device.DeviceType = "Building Controller"
			device.Protocol = "BACnet"
		case 80, 443:
			if device.DeviceType == "" {
				device.DeviceType = "HMI/Web Interface"
			}
		}
	}
	
	if device.DeviceType == "" {
		device.DeviceType = "Unknown Device"
	}
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