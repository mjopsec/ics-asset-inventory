package models

import (
	"time"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Asset represents an industrial asset/device
type Asset struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Name        string         `gorm:"not null" json:"name" validate:"required"`
	Description string         `json:"description"`
	AssetType   string         `gorm:"not null" json:"asset_type" validate:"required"` // PLC, HMI, RTU, etc.
	
	// Network Information
	IPAddress   string `gorm:"index" json:"ip_address"`
	MACAddress  string `gorm:"index" json:"mac_address"`
	Port        int    `json:"port"`
	Protocol    string `json:"protocol"` // Modbus, DNP3, EtherNet/IP, etc.
	
	// Device Information
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	Version     string `json:"version"`
	SerialNumber string `json:"serial_number"`
	
	// Operational Status
	Status      string    `gorm:"default:'unknown'" json:"status"` // online, offline, unknown, error
	LastSeen    time.Time `json:"last_seen"`
	Uptime      int64     `json:"uptime"` // in seconds
	
	// Location & Organization
	Location    string `json:"location"`
	Zone        string `json:"zone"` // DMZ, Control Network, etc.
	Site        string `json:"site"`
	Department  string `json:"department"`
	
	// Security Information
	Criticality    string `gorm:"default:'medium'" json:"criticality"` // low, medium, high, critical
	SecurityLevel  string `json:"security_level"`
	LastSecScan    time.Time `json:"last_security_scan"`
	VulnCount      int    `json:"vulnerability_count"`
	
	// Relationships
	GroupID     *uuid.UUID `gorm:"type:uuid" json:"group_id"`
	Group       *AssetGroup `gorm:"foreignKey:GroupID" json:"group,omitempty"`
	
	// Metadata
	Tags        []AssetTag    `gorm:"many2many:asset_tags;" json:"tags"`
	Attributes  []AssetAttribute `gorm:"foreignKey:AssetID" json:"attributes"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate hook untuk generate UUID sebelum create
func (a *Asset) BeforeCreate(tx *gorm.DB) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	return nil
}

// AssetGroup for organizing assets
type AssetGroup struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Name        string         `gorm:"not null;unique" json:"name" validate:"required"`
	Description string         `json:"description"`
	Color       string         `gorm:"default:'#3B82F6'" json:"color"`
	
	Assets      []Asset        `gorm:"foreignKey:GroupID" json:"assets,omitempty"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate hook untuk AssetGroup
func (ag *AssetGroup) BeforeCreate(tx *gorm.DB) error {
	if ag.ID == uuid.Nil {
		ag.ID = uuid.New()
	}
	return nil
}

// AssetTag for flexible tagging
type AssetTag struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Name        string         `gorm:"not null;unique" json:"name" validate:"required"`
	Color       string         `gorm:"default:'#6B7280'" json:"color"`
	
	Assets      []Asset        `gorm:"many2many:asset_tags;" json:"assets,omitempty"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// BeforeCreate hook untuk SystemConfig
func (sc *SystemConfig) BeforeCreate(tx *gorm.DB) error {
	if sc.ID == uuid.Nil {
		sc.ID = uuid.New()
	}
	return nil
}

// BeforeCreate hook untuk AssetTag
func (at *AssetTag) BeforeCreate(tx *gorm.DB) error {
	if at.ID == uuid.Nil {
		at.ID = uuid.New()
	}
	return nil
}

// AssetAttribute for custom key-value pairs
type AssetAttribute struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	AssetID     uuid.UUID      `gorm:"type:uuid;not null" json:"asset_id"`
	Key         string         `gorm:"not null" json:"key" validate:"required"`
	Value       string         `json:"value"`
	ValueType   string         `gorm:"default:'string'" json:"value_type"` // string, number, boolean, json
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// BeforeCreate hook untuk AssetAttribute
func (aa *AssetAttribute) BeforeCreate(tx *gorm.DB) error {
	if aa.ID == uuid.Nil {
		aa.ID = uuid.New()
	}
	return nil
}

// NetworkScan represents network discovery results
type NetworkScan struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	ScanType    string         `gorm:"not null" json:"scan_type"` // network, protocol, security
	Target      string         `gorm:"not null" json:"target"` // IP range, single IP, etc.
	Status      string         `gorm:"default:'pending'" json:"status"` // pending, running, completed, failed
	
	StartTime   time.Time      `json:"start_time"`
	EndTime     *time.Time     `json:"end_time"`
	Duration    int64          `json:"duration"` // in seconds
	
	DevicesFound int           `json:"devices_found"`
	Results      string        `gorm:"type:text" json:"results"` // JSON results
	ErrorMsg     string        `json:"error_message"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// BeforeCreate hook untuk NetworkScan
func (ns *NetworkScan) BeforeCreate(tx *gorm.DB) error {
	if ns.ID == uuid.Nil {
		ns.ID = uuid.New()
	}
	return nil
}

// SecurityAssessment for vulnerability tracking
type SecurityAssessment struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	AssetID     uuid.UUID      `gorm:"type:uuid;not null" json:"asset_id"`
	Asset       Asset          `gorm:"foreignKey:AssetID" json:"asset"`
	
	ScanDate    time.Time      `json:"scan_date"`
	ScanType    string         `json:"scan_type"` // port, protocol, vulnerability
	
	Severity    string         `json:"severity"` // low, medium, high, critical
	Title       string         `json:"title"`
	Description string         `gorm:"type:text" json:"description"`
	CVE         string         `json:"cve"`
	CVSS        float64        `json:"cvss_score"`
	
	Status      string         `gorm:"default:'open'" json:"status"` // open, acknowledged, resolved, false_positive
	Remediation string         `gorm:"type:text" json:"remediation"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// BeforeCreate hook untuk SecurityAssessment
func (sa *SecurityAssessment) BeforeCreate(tx *gorm.DB) error {
	if sa.ID == uuid.Nil {
		sa.ID = uuid.New()
	}
	return nil
}

// User for basic authentication
type User struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Username    string         `gorm:"not null;unique" json:"username" validate:"required"`
	Email       string         `gorm:"not null;unique" json:"email" validate:"required,email"`
	Password    string         `gorm:"not null" json:"-"`
	Role        string         `gorm:"default:'viewer'" json:"role"` // admin, operator, viewer
	
	Active      bool           `gorm:"default:true" json:"active"`
	LastLogin   *time.Time     `json:"last_login"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// BeforeCreate hook untuk User
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}

// SystemConfig for application settings
type SystemConfig struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key" json:"id"`
	Key         string         `gorm:"not null;unique" json:"key" validate:"required"`
	Value       string         `gorm:"type:text" json:"value"`
	ValueType   string         `gorm:"default:'string'" json:"value_type"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}