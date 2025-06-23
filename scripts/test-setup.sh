#!/bin/bash
# scripts/test-setup.sh

echo "🔧 Testing ICS Asset Inventory Setup..."

# Test 1: Build application
echo "1. Building application..."
go build -o bin/server cmd/server/main.go
if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Test 2: Check config file
echo "2. Checking configuration..."
if [ -f "configs/config.yaml" ]; then
    echo "✅ Config file exists"
else
    echo "❌ Config file missing"
    exit 1
fi

# Test 3: Test database initialization (dry run)
echo "3. Testing database initialization..."
timeout 10s ./bin/server &
SERVER_PID=$!
sleep 3

# Check if server started
if ps -p $SERVER_PID > /dev/null; then
    echo "✅ Server started successfully"
    kill $SERVER_PID
else
    echo "❌ Server failed to start"
    exit 1
fi

# Test 4: Check database file creation
echo "4. Checking database creation..."
if [ -f "ics_inventory.db" ]; then
    echo "✅ Database file created"
    
    # Check tables
    echo "5. Checking database tables..."
    TABLES=$(sqlite3 ics_inventory.db ".tables")
    if [[ $TABLES == *"assets"* ]]; then
        echo "✅ Assets table exists"
    else
        echo "❌ Assets table missing"
    fi
    
    if [[ $TABLES == *"asset_groups"* ]]; then
        echo "✅ Asset groups table exists"
    else
        echo "❌ Asset groups table missing"
    fi
else
    echo "❌ Database file not created"
fi

echo "🎉 Setup test completed!"
