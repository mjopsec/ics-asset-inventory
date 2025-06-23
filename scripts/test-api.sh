#!/bin/bash
# scripts/test-api.sh

echo "🧪 Testing ICS Asset Inventory API..."

BASE_URL="http://localhost:8080"

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to test API endpoint
test_endpoint() {
    local method=$1
    local endpoint=$2
    local expected_status=$3
    local description=$4
    local data=$5

    echo -n "Testing $description... "

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json "$BASE_URL$endpoint")
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -w "%{http_code}" -o /tmp/response.json -H "Content-Type: application/json" -d "$data" -X POST "$BASE_URL$endpoint")
    fi

    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✅ PASS${NC}"
        return 0
    else
        echo -e "${RED}❌ FAIL (Expected: $expected_status, Got: $response)${NC}"
        echo "Response body:"
        cat /tmp/response.json
        echo ""
        return 1
    fi
}

# Wait for server to be ready
echo "⏳ Waiting for server to start..."
for i in {1..30}; do
    if curl -s "$BASE_URL/health" > /dev/null 2>&1; then
        break
    fi
    sleep 1
    if [ $i -eq 30 ]; then
        echo -e "${RED}❌ Server failed to start within 30 seconds${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ Server is running${NC}"
echo ""

# Test health endpoints
echo -e "${YELLOW}=== Health Check Endpoints ===${NC}"
test_endpoint "GET" "/health" "200" "Health check"
test_endpoint "GET" "/api/health" "200" "API health check"
test_endpoint "GET" "/ready" "200" "Readiness check"
test_endpoint "GET" "/api/system/info" "200" "System info"
test_endpoint "GET" "/api/system/database" "200" "Database status"

echo ""

# Test asset endpoints
echo -e "${YELLOW}=== Asset Endpoints ===${NC}"
test_endpoint "GET" "/api/assets" "200" "Get all assets"
test_endpoint "GET" "/api/assets/stats" "200" "Get asset statistics"

# Test dashboard endpoints
echo ""
echo -e "${YELLOW}=== Dashboard Endpoints ===${NC}"
test_endpoint "GET" "/api/dashboard/overview" "200" "Dashboard overview"
test_endpoint "GET" "/api/dashboard/metrics" "200" "Dashboard metrics"
test_endpoint "GET" "/api/dashboard/alerts" "200" "Dashboard alerts"

# Test group endpoints
echo ""
echo -e "${YELLOW}=== Group Endpoints ===${NC}"
test_endpoint "GET" "/api/groups" "200" "Get all groups"

# Test web pages
echo ""
echo -e "${YELLOW}=== Web Pages ===${NC}"
test_endpoint "GET" "/" "200" "Main dashboard page"
test_endpoint "GET" "/assets" "200" "Assets page"
test_endpoint "GET" "/discovery" "200" "Discovery page"
test_endpoint "GET" "/security" "200" "Security page"

# Test asset creation
echo ""
echo -e "${YELLOW}=== Asset Creation Test ===${NC}"
asset_data='{
    "name": "Test PLC Device",
    "asset_type": "PLC",
    "ip_address": "192.168.1.200",
    "vendor": "Test Vendor",
    "model": "Test Model",
    "criticality": "medium",
    "status": "unknown"
}'

test_endpoint "POST" "/api/assets" "201" "Create new asset" "$asset_data"

echo ""
echo -e "${GREEN}🎉 API testing completed!${NC}"

# Clean up
rm -f /tmp/response.json
