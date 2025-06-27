#!/bin/bash

# Test Network Discovery API

API_URL="http://localhost:8080/api"
TOKEN=""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ $2${NC}"
    else
        echo -e "${RED}✗ $2${NC}"
    fi
}

echo "=== ICS Asset Inventory - Network Discovery Test ==="
echo ""

# 1. Login first
echo "1. Testing Authentication..."
LOGIN_RESPONSE=$(curl -s -X POST $API_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }')

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.token')

if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
    print_status 0 "Login successful"
    echo "   Token: ${TOKEN:0:20}..."
else
    print_status 1 "Login failed"
    echo "   Response: $LOGIN_RESPONSE"
    exit 1
fi

echo ""

# 2. Get protocol ports info
echo "2. Getting Protocol Ports Information..."
PORTS_RESPONSE=$(curl -s -X GET $API_URL/discovery/protocol-ports \
  -H "Authorization: Bearer $TOKEN")

if [ $? -eq 0 ]; then
    print_status 0 "Protocol ports retrieved"
    echo "$PORTS_RESPONSE" | jq '.'
else
    print_status 1 "Failed to get protocol ports"
fi

echo ""

# 3. Check for active scans
echo "3. Checking for Active Scans..."
ACTIVE_RESPONSE=$(curl -s -X GET $API_URL/discovery/active-scans \
  -H "Authorization: Bearer $TOKEN")

if [ $? -eq 0 ]; then
    print_status 0 "Active scans checked"
    echo "$ACTIVE_RESPONSE" | jq '.'
else
    print_status 1 "Failed to check active scans"
fi

echo ""

# 4. Start a network scan
echo "4. Starting Network Scan..."
echo "   Target: 192.168.1.0/24 (local network)"
echo "   Type: quick"
echo "   Protocols: modbus, dnp3, s7"

SCAN_RESPONSE=$(curl -s -X POST $API_URL/discovery/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_range": "192.168.1.0/24",
    "scan_type": "quick",
    "timeout": 30,
    "max_concurrent": 50,
    "protocols": ["modbus", "dnp3", "s7", "ethernet_ip", "bacnet", "snmp"]
  }')

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')

if [ "$SCAN_ID" != "null" ] && [ -n "$SCAN_ID" ]; then
    print_status 0 "Scan started successfully"
    echo "   Scan ID: $SCAN_ID"
    echo "$SCAN_RESPONSE" | jq '.'
else
    print_status 1 "Failed to start scan"
    echo "   Response: $SCAN_RESPONSE"
    exit 1
fi

echo ""

# 5. Monitor scan progress
echo "5. Monitoring Scan Progress..."
echo "   Checking every 5 seconds..."

for i in {1..12}; do
    sleep 5
    
    PROGRESS_RESPONSE=$(curl -s -X GET $API_URL/discovery/scan/$SCAN_ID/progress \
      -H "Authorization: Bearer $TOKEN")
    
    STATUS=$(echo $PROGRESS_RESPONSE | jq -r '.status')
    PROGRESS=$(echo $PROGRESS_RESPONSE | jq -r '.progress')
    DISCOVERED=$(echo $PROGRESS_RESPONSE | jq -r '.discovered_hosts')
    
    echo -e "${YELLOW}   Progress: ${PROGRESS}% | Status: $STATUS | Devices Found: $DISCOVERED${NC}"
    
    if [ "$STATUS" == "completed" ] || [ "$STATUS" == "failed" ] || [ "$STATUS" == "cancelled" ]; then
        break
    fi
done

echo ""

# 6. Get scan results
echo "6. Getting Scan Results..."
RESULTS_RESPONSE=$(curl -s -X GET $API_URL/discovery/scan/$SCAN_ID/results \
  -H "Authorization: Bearer $TOKEN")

DEVICE_COUNT=$(echo $RESULTS_RESPONSE | jq '.devices | length')

if [ $? -eq 0 ]; then
    print_status 0 "Results retrieved"
    echo "   Devices found: $DEVICE_COUNT"
    
    if [ "$DEVICE_COUNT" -gt 0 ]; then
        echo ""
        echo "   Discovered Devices:"
        echo "$RESULTS_RESPONSE" | jq -r '.devices[] | "   - \(.ip_address) | \(.device_type) | \(.protocol // "Unknown")"'
    fi
else
    print_status 1 "Failed to get results"
fi

echo ""

# 7. Get scan history
echo "7. Getting Scan History..."
HISTORY_RESPONSE=$(curl -s -X GET "$API_URL/discovery/history?limit=5" \
  -H "Authorization: Bearer $TOKEN")

if [ $? -eq 0 ]; then
    print_status 0 "History retrieved"
    echo "$HISTORY_RESPONSE" | jq '.history[] | {id: .id, target: .target, status: .status, devices_found: .devices_found}'
else
    print_status 1 "Failed to get history"
fi

echo ""

# 8. Add a device to inventory (if any found)
if [ "$DEVICE_COUNT" -gt 0 ]; then
    echo "8. Adding First Device to Inventory..."
    
    FIRST_DEVICE_IP=$(echo $RESULTS_RESPONSE | jq -r '.devices[0].ip_address')
    
    ADD_RESPONSE=$(curl -s -X POST $API_URL/discovery/scan/$SCAN_ID/add-device \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "{\"device_ip\": \"$FIRST_DEVICE_IP\"}")
    
    if [ $? -eq 0 ]; then
        print_status 0 "Device added to inventory"
        echo "$ADD_RESPONSE" | jq '.'
    else
        print_status 1 "Failed to add device"
    fi
fi

echo ""
echo "=== Test Complete ==="

# Optional: Test WebSocket connection
echo ""
echo "To test WebSocket connection, you can use:"
echo "wscat -c \"ws://localhost:8080/ws/events?token=$TOKEN\""
echo "or"
echo "websocat \"ws://localhost:8080/ws/events?token=$TOKEN\""
