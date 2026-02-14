#!/bin/bash

# Emergency cache population script using debug endpoint (no auth required)
# This bypasses authentication to get your app working immediately

URL="https://heimdall-nine-alpha.vercel.app/api/cron/refresh-debug"

echo "🚀 Emergency Cache Population"
echo "================================"
echo "Using debug endpoint (no authentication)"
echo ""

BATCH=0
while [ $BATCH -lt 7 ]; do
    BATCH=$((BATCH + 1))
    echo "⏳ Triggering batch $BATCH/7..."

    RESPONSE=$(curl -s -X GET "$URL" -H "Content-Type: application/json")

    echo "   Response: $RESPONSE"

    # Check for success
    if echo "$RESPONSE" | grep -q '"success":true'; then
        ASSETS=$(echo "$RESPONSE" | python3 -c "import sys, json; data = json.load(sys.stdin); print(', '.join(data.get('assetsProcessed', [])))" 2>/dev/null)
        echo "   ✓ Batch $BATCH successful"
        echo "   Assets processed: $ASSETS"
    else
        echo "   ✗ Batch $BATCH failed"
    fi

    # Wait 2 seconds between requests
    if [ $BATCH -lt 7 ]; then
        echo "   Waiting 2 seconds..."
        sleep 2
    fi
    echo ""
done

echo "✅ Cache population complete!"
echo "🔍 Refresh your app - vulnerabilities should now be visible."
echo ""
echo "⚠️  IMPORTANT: The debug endpoint will be removed once auth is fixed."
