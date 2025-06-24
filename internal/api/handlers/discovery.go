package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"ics-asset-inventory/internal/services"

	"github.com/gin-gonic/gin"
)

// DiscoveryHandler handles network discovery operations
type DiscoveryHandler struct {
	scanService *services.ScanService
}

// NewDiscoveryHandler creates a new discovery handler
func NewDiscoveryHandler() *DiscoveryHandler {
	return &DiscoveryHandler{
		scanService: services.NewScanService(),
	}
}

// StartScan initiates a new network scan
// @Summary Start network scan
// @Description Initiate a new network discovery scan
// @Tags discovery
// @Accept json
// @Produce json
// @Param scan body services.ScanRequest true "Scan configuration"
// @Success 200 {object} services.ScanResponse
// @Failure 400 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/discovery/scan [post]
func (h *DiscoveryHandler) StartScan(c *gin.Context) {
	var req services.ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Set defaults if not provided
	if req.Timeout == 0 {
		req.Timeout = 30
	}
	if req.MaxConcurrent == 0 {
		req.MaxConcurrent = 50
	}
	if len(req.Protocols) == 0 {
		req.Protocols = []string{"modbus", "dnp3", "bacnet", "ethernet_ip", "s7", "snmp"}
	}

	response, err := h.scanService.StartScan(&req)
	if err != nil {
		if err.Error() == "a scan is already in progress" {
			c.JSON(http.StatusConflict, gin.H{
				"error": err.Error(),
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to start scan",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, response)
}

// StopScan stops a running scan
// @Summary Stop network scan
// @Description Stop a currently running network scan
// @Tags discovery
// @Accept json
// @Produce json
// @Param id path string true "Scan ID"
// @Success 200 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/discovery/scan/{id}/stop [post]
func (h *DiscoveryHandler) StopScan(c *gin.Context) {
	scanID := c.Param("id")
	
	if err := h.scanService.StopScan(scanID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Scan stopped successfully",
		"scan_id": scanID,
	})
}

// GetScanProgress returns scan progress
// @Summary Get scan progress
// @Description Get the progress of a network scan
// @Tags discovery
// @Accept json
// @Produce json
// @Param id path string true "Scan ID"
// @Success 200 {object} services.ScanProgressResponse
// @Failure 404 {object} map[string]string
// @Router /api/discovery/scan/{id}/progress [get]
func (h *DiscoveryHandler) GetScanProgress(c *gin.Context) {
	scanID := c.Param("id")
	
	progress, err := h.scanService.GetScanProgress(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, progress)
}

// GetScanResults returns discovered devices
// @Summary Get scan results
// @Description Get discovered devices from a network scan
// @Tags discovery
// @Accept json
// @Produce json
// @Param id path string true "Scan ID"
// @Success 200 {array} services.DiscoveredDevice
// @Failure 404 {object} map[string]string
// @Router /api/discovery/scan/{id}/results [get]
func (h *DiscoveryHandler) GetScanResults(c *gin.Context) {
	scanID := c.Param("id")
	
	results, err := h.scanService.GetScanResults(scanID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scan_id": scanID,
		"devices": results,
		"count": len(results),
	})
}

// GetScanHistory returns scan history
// @Summary Get scan history
// @Description Get history of network scans
// @Tags discovery
// @Accept json
// @Produce json
// @Param limit query int false "Number of records to return" default(20)
// @Success 200 {array} models.NetworkScan
// @Router /api/discovery/history [get]
func (h *DiscoveryHandler) GetScanHistory(c *gin.Context) {
	limit := 20
	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	history, err := h.scanService.GetScanHistory(limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to fetch scan history",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"history": history,
		"count": len(history),
	})
}

// AddDeviceToInventory adds a discovered device to the asset inventory
// @Summary Add device to inventory
// @Description Add a discovered device to the asset inventory
// @Tags discovery
// @Accept json
// @Produce json
// @Param id path string true "Scan ID"
// @Param device body map[string]string true "Device info"
// @Success 201 {object} models.Asset
// @Failure 400 {object} map[string]string
// @Router /api/discovery/scan/{id}/add-device [post]
func (h *DiscoveryHandler) AddDeviceToInventory(c *gin.Context) {
	scanID := c.Param("id")
	
	var req struct {
		DeviceIP string `json:"device_ip" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	asset, err := h.scanService.AddDeviceToInventory(scanID, req.DeviceIP)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to add device to inventory",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Device added to inventory successfully",
		"asset": asset,
	})
}

// AddAllDevicesToInventory adds all discovered devices to inventory
// @Summary Add all devices to inventory
// @Description Add all discovered devices from a scan to the asset inventory
// @Tags discovery
// @Accept json
// @Produce json
// @Param id path string true "Scan ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Router /api/discovery/scan/{id}/add-all-devices [post]
func (h *DiscoveryHandler) AddAllDevicesToInventory(c *gin.Context) {
	scanID := c.Param("id")
	
	// Get all devices from scan
	devices, err := h.scanService.GetScanResults(scanID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to get scan results",
			"details": err.Error(),
		})
		return
	}

	added := 0
	updated := 0
	skipped := 0
	errors := []string{}

	for _, device := range devices {
		// Skip devices already in inventory
		if device.InInventory {
			skipped++
			continue
		}
		
		_, err := h.scanService.AddDeviceToInventory(scanID, device.IPAddress)
		if err != nil {
			if err.Error() == "device already in inventory" {
				skipped++
			} else {
				errors = append(errors, fmt.Sprintf("%s: %s", device.IPAddress, err.Error()))
			}
		} else {
			if device.IsNew {
				added++
			} else {
				updated++
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Devices processed",
		"added": added,
		"updated": updated,
		"skipped": skipped,
		"errors": errors,
		"total": len(devices),
	})
}

// GetProtocolPorts returns default ports for protocols
// @Summary Get protocol ports
// @Description Get default port numbers for industrial protocols
// @Tags discovery
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/discovery/protocol-ports [get]
func (h *DiscoveryHandler) GetProtocolPorts(c *gin.Context) {
	protocolPorts := map[string]interface{}{
		"modbus": map[string]interface{}{
			"name": "Modbus TCP/RTU",
			"default_port": 502,
			"alternate_ports": []int{},
		},
		"dnp3": map[string]interface{}{
			"name": "DNP3",
			"default_port": 20000,
			"alternate_ports": []int{20547},
		},
		"ethernet_ip": map[string]interface{}{
			"name": "EtherNet/IP",
			"default_port": 44818,
			"alternate_ports": []int{2222},
		},
		"bacnet": map[string]interface{}{
			"name": "BACnet",
			"default_port": 47808,
			"alternate_ports": []int{},
		},
		"s7": map[string]interface{}{
			"name": "Siemens S7",
			"default_port": 102,
			"alternate_ports": []int{},
		},
		"iec104": map[string]interface{}{
			"name": "IEC 60870-5-104",
			"default_port": 2404,
			"alternate_ports": []int{},
		},
		"snmp": map[string]interface{}{
			"name": "SNMP",
			"default_port": 161,
			"alternate_ports": []int{162},
		},
	}

	c.JSON(http.StatusOK, protocolPorts)
}

// GetActiveScans returns currently active scans
// @Summary Get active scans
// @Description Get list of currently running scans
// @Tags discovery
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /api/discovery/active-scans [get]
func (h *DiscoveryHandler) GetActiveScans(c *gin.Context) {
	activeScan := h.scanService.GetActiveScan()
	
	if activeScan == nil {
		c.JSON(http.StatusOK, gin.H{
			"active_scans": []interface{}{},
			"count": 0,
		})
		return
	}

	// Return active scan info
	c.JSON(http.StatusOK, gin.H{
		"active_scans": []interface{}{
			gin.H{
				"scan_id": activeScan.ID,
				"status": "running",
				"start_time": activeScan.ScanDB.StartTime,
			},
		},
		"count": 1,
	})
}