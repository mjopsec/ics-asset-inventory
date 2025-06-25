package protocols

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ProtocolDetector interface for protocol-specific detection
type ProtocolDetector interface {
	Detect(host string, port uint16) (*DeviceInfo, error)
	GetDefaultPort() uint16
	GetProtocolName() string
}

// DeviceInfo contains information about a detected device
type DeviceInfo struct {
	Protocol     string
	DeviceType   string
	Vendor       string
	Model        string
	Version      string
	SerialNumber string
	Fingerprint  map[string]interface{}
}

// ModbusDetector detects Modbus devices
type ModbusDetector struct{}

func (m *ModbusDetector) GetDefaultPort() uint16 {
	return 502
}

func (m *ModbusDetector) GetProtocolName() string {
	return "Modbus TCP"
}

func (m *ModbusDetector) Detect(host string, port uint16) (*DeviceInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send Modbus identification request (Function code 0x2B)
	request := []byte{
		0x00, 0x00, // Transaction ID
		0x00, 0x00, // Protocol ID
		0x00, 0x06, // Length
		0x01,       // Unit ID
		0x2B,       // Function code (Read Device Identification)
		0x0E,       // MEI type
		0x01,       // Read Device ID code
		0x00,       // Object ID
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Basic validation
	if n < 8 || response[7] != 0x2B {
		// Try a simple read holding registers as fallback
		return m.detectWithReadHolding(conn)
	}

	// Parse device identification
	info := &DeviceInfo{
		Protocol:    "Modbus TCP",
		DeviceType:  "PLC",
		Fingerprint: make(map[string]interface{}),
	}

	// Parse response for vendor, model, etc.
	if n > 14 {
		info.Vendor = "Modbus Device"
		info.Model = "Generic"
	}

	return info, nil
}

func (m *ModbusDetector) detectWithReadHolding(conn net.Conn) (*DeviceInfo, error) {
	// Send read holding registers request
	request := []byte{
		0x00, 0x01, // Transaction ID
		0x00, 0x00, // Protocol ID
		0x00, 0x06, // Length
		0x01,       // Unit ID
		0x03,       // Function code (Read Holding Registers)
		0x00, 0x00, // Starting address
		0x00, 0x01, // Quantity
	}

	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	if n >= 9 && response[7] == 0x03 {
		return &DeviceInfo{
			Protocol:   "Modbus TCP",
			DeviceType: "Modbus Device",
			Vendor:     "Unknown",
			Model:      "Unknown",
		}, nil
	}

	return nil, fmt.Errorf("invalid Modbus response")
}

// DNP3Detector detects DNP3 devices
type DNP3Detector struct{}

func (d *DNP3Detector) GetDefaultPort() uint16 {
	return 20000
}

func (d *DNP3Detector) GetProtocolName() string {
	return "DNP3"
}

func (d *DNP3Detector) Detect(host string, port uint16) (*DeviceInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send DNP3 link layer test frame
	request := []byte{
		0x05, 0x64, // Start bytes
		0x05,       // Length
		0xC0,       // Control byte (primary, FCB=0, FCV=0, func=0)
		0x01, 0x00, // Destination address (1)
		0x00, 0x00, // Source address (0)
		0x65, 0xE4, // CRC
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Check DNP3 start bytes
	if n >= 2 && response[0] == 0x05 && response[1] == 0x64 {
		return &DeviceInfo{
			Protocol:   "DNP3",
			DeviceType: "RTU/Outstation",
			Vendor:     "DNP3 Compatible",
			Model:      "Unknown",
		}, nil
	}

	return nil, fmt.Errorf("not a DNP3 device")
}

// BACnetDetector detects BACnet devices
type BACnetDetector struct{}

func (b *BACnetDetector) GetDefaultPort() uint16 {
	return 47808
}

func (b *BACnetDetector) GetProtocolName() string {
	return "BACnet"
}

func (b *BACnetDetector) Detect(host string, port uint16) (*DeviceInfo, error) {
	// BACnet typically uses UDP
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send BACnet Who-Is request
	request := []byte{
		0x81,       // Type: BACnet/IP
		0x0A,       // Function: Original-Unicast-NPDU
		0x00, 0x11, // Length
		0x01, 0x04, // BVLC Header
		0x00, 0x05, // NPDU
		0x01,       // Version
		0x00,       // Control
		0x10, 0x08, // Who-Is
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Check for BACnet response
	if n > 4 && response[0] == 0x81 {
		return &DeviceInfo{
			Protocol:   "BACnet",
			DeviceType: "Building Controller",
			Vendor:     "BACnet Device",
			Model:      "Unknown",
		}, nil
	}

	return nil, fmt.Errorf("not a BACnet device")
}

// EtherNetIPDetector detects EtherNet/IP devices
type EtherNetIPDetector struct{}

func (e *EtherNetIPDetector) GetDefaultPort() uint16 {
	return 44818
}

func (e *EtherNetIPDetector) GetProtocolName() string {
	return "EtherNet/IP"
}

func (e *EtherNetIPDetector) Detect(host string, port uint16) (*DeviceInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send EtherNet/IP List Identity request
	request := []byte{
		// Encapsulation header
		0x63, 0x00, // Command: List Identity
		0x00, 0x00, // Length
		0x00, 0x00, 0x00, 0x00, // Session handle
		0x00, 0x00, 0x00, 0x00, // Status
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Context
		0x00, 0x00, 0x00, 0x00, // Options
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Check for EtherNet/IP response
	if n >= 24 && response[0] == 0x63 && response[1] == 0x00 {
		info := &DeviceInfo{
			Protocol:   "EtherNet/IP",
			DeviceType: "PLC",
			Vendor:     "Rockwell/Allen-Bradley",
			Model:      "Unknown",
		}

		// Try to parse vendor and product info
		if n > 44 {
			// Parse identity object if available
			info.Vendor = "EtherNet/IP Device"
		}

		return info, nil
	}

	return nil, fmt.Errorf("not an EtherNet/IP device")
}

// S7Detector detects Siemens S7 devices
type S7Detector struct{}

func (s *S7Detector) GetDefaultPort() uint16 {
	return 102
}

func (s *S7Detector) GetProtocolName() string {
	return "Siemens S7"
}

func (s *S7Detector) Detect(host string, port uint16) (*DeviceInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send S7 connection request (COTP CR)
	request := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT Header
		0x11,                   // COTP Length
		0xE0,                   // COTP PDU Type (CR)
		0x00, 0x00,             // Destination reference
		0x00, 0x01,             // Source reference
		0x00,                   // Class/Options
		0xC1, 0x02, 0x01, 0x00, // Parameter 1
		0xC2, 0x02, 0x01, 0x02, // Parameter 2
		0xC0, 0x01, 0x09, // Parameter 3
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 256)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Check for S7 response
	if n >= 6 && response[0] == 0x03 && response[5] == 0xD0 {
		return &DeviceInfo{
			Protocol:   "Siemens S7",
			DeviceType: "PLC",
			Vendor:     "Siemens",
			Model:      "S7 PLC",
		}, nil
	}

	return nil, fmt.Errorf("not a Siemens S7 device")
}

// SNMPDetector detects SNMP devices
type SNMPDetector struct{}

func (s *SNMPDetector) GetDefaultPort() uint16 {
	return 161
}

func (s *SNMPDetector) GetProtocolName() string {
	return "SNMP"
}

func (s *SNMPDetector) Detect(host string, port uint16) (*DeviceInfo, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send SNMP v1 GetRequest for sysDescr (1.3.6.1.2.1.1.1.0)
	request := []byte{
		0x30, 0x26, // SEQUENCE
		0x02, 0x01, 0x00, // Version: 1
		0x04, 0x06, 0x70, 0x75, 0x62, 0x6C, 0x69, 0x63, // Community: "public"
		0xA0, 0x19, // GetRequest PDU
		0x02, 0x01, 0x01, // Request ID: 1
		0x02, 0x01, 0x00, // Error Status: 0
		0x02, 0x01, 0x00, // Error Index: 0
		0x30, 0x0E, // Variable bindings
		0x30, 0x0C, // Variable binding
		0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: sysDescr
		0x05, 0x00, // NULL value
	}

	conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	response := make([]byte, 1024)
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	// Basic SNMP response validation
	if n > 2 && response[0] == 0x30 {
		return &DeviceInfo{
			Protocol:   "SNMP",
			DeviceType: "Network Device",
			Vendor:     "SNMP Enabled",
			Model:      "Unknown",
		}, nil
	}

	return nil, fmt.Errorf("not an SNMP device")
}

// GetAllDetectors returns all available protocol detectors
func GetAllDetectors() map[string]ProtocolDetector {
	return map[string]ProtocolDetector{
		"modbus":      &ModbusDetector{},
		"dnp3":        &DNP3Detector{},
		"bacnet":      &BACnetDetector{},
		"ethernet_ip": &EtherNetIPDetector{},
		"s7":          &S7Detector{},
		"snmp":        &SNMPDetector{},
	}
}