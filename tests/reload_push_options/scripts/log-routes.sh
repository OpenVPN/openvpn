#!/bin/bash
# Log current routes to results file
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
ROUTES_FILE="/results/routes_${common_name:-unknown}_${TIMESTAMP}.txt"

echo "=== Route event at $TIMESTAMP ===" >> "$ROUTES_FILE"
echo "Script: $script_type" >> "$ROUTES_FILE"
echo "Routes:" >> "$ROUTES_FILE"
ip route show >> "$ROUTES_FILE"
echo "" >> "$ROUTES_FILE"



