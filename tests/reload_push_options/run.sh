#!/bin/bash
# Test suite for reload-push-options management command
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    info "Debug: Server logs (last 30 lines):"
    docker compose exec -T server tail -30 /var/log/openvpn.log 2>/dev/null || true
    info "Debug: Client1 logs (last 30 lines):"
    docker compose exec -T client1 tail -30 /results/client1.log 2>/dev/null || true
    docker compose down -v 2>/dev/null || true
    exit 1
}
info() { echo -e "${YELLOW}→${NC} $1"; }

mgmt() {
    echo "$1" | nc -q1 localhost 7505 2>/dev/null || echo "$1" | nc -w1 localhost 7505 2>/dev/null
}

get_client_log_lines() {
    local client="$1"
    docker compose exec -T "$client" wc -l /results/${client}.log 2>/dev/null | awk '{print $1}' || echo "0"
}

wait_for_client_ready() {
    local client="$1"
    local lines_before="$2"
    local max_wait=20

    for i in $(seq 1 $max_wait); do
        sleep 1
        if docker compose exec -T "$client" tail -n +$((lines_before + 1)) /results/${client}.log 2>/dev/null | grep -q "Initialization Sequence Completed"; then
            return 0
        fi
    done
    return 1
}

get_client_routes() {
    local client="$1"
    if ! docker compose exec -T "$client" ip link show tun0 &>/dev/null; then
        echo "(tun0 not found)"
        return
    fi
    docker compose exec -T "$client" ip route show 2>/dev/null | grep -E "^(192\.168\.|10\.|172\.)" || echo "(no matching routes)"
}

update_server_config() {
    local config_content="$1"
    # Generate config from template inside the container using envsubst
    docker compose exec -T -e PUSH_OPTIONS="$config_content" server \
        sh -c 'envsubst '"'"'${PUSH_OPTIONS}'"'"' < /etc/openvpn/server.conf.default > /etc/openvpn/server.conf'
}

wait_for_clients() {
    info "Waiting for clients to connect..."
    for i in {1..30}; do
        local count=$(mgmt "status" | grep -c "^client" || true)
        if [ "$count" -ge 2 ]; then
            return 0
        fi
        sleep 1
    done
    fail "Clients did not connect in time"
}

cleanup() {
    info "Cleaning up..."
    docker compose down -v 2>/dev/null || true
    rm -rf results/*
}

# Run test: update config, reload (with or without update-clients), verify routes
# Args: test_name, client, update_clients (0|1|skip), config_content, must_have_pattern, must_not_have_pattern
# update_clients=skip: don't send mgmt command, just verify routes (for reconnect tests)
run_test() {
    local test_name="$1"
    local client="$2"
    local update_clients="$3"
    local config_content="$4"
    local must_have="$5"
    local must_not_have="$6"

    echo ""
    echo "--- $test_name ---"

    local routes_before=$(get_client_routes "$client")
    local log_lines=$(get_client_log_lines "$client")

    update_server_config "$config_content"

    if [ "$update_clients" != "skip" ]; then
        local cmd="reload-push-options"
        [ "$update_clients" = "1" ] && cmd="reload-push-options update-clients"

        local result=$(mgmt "$cmd")
        echo "Management response: $result"

        if ! echo "$result" | grep -q "SUCCESS"; then
            fail "$test_name: command failed"
        fi
        pass "$test_name: command succeeded"

        if [ "$update_clients" = "1" ]; then
            wait_for_client_ready "$client" "$log_lines"
        else
            sleep 2
        fi
    fi

    local routes=$(get_client_routes "$client")
    info "Routes: $routes"

    if [ -n "$must_have" ]; then
        if echo "$routes" | grep -qE "$must_have"; then
            pass "$test_name: expected routes present"
        else
            fail "$test_name: expected routes ($must_have) not found"
        fi
    fi

    if [ -n "$must_not_have" ]; then
        if echo "$routes" | grep -qE "$must_not_have"; then
            fail "$test_name: removed routes ($must_not_have) still present"
        else
            pass "$test_name: routes correctly removed"
        fi
    fi
}

trap cleanup EXIT

# Generate keys if needed
if [ ! -f keys/ca.crt ]; then
    info "Generating test PKI..."
    chmod +x scripts/gen-keys.sh
    ./scripts/gen-keys.sh
fi

chmod +x scripts/*.sh
rm -rf results/*
mkdir -p results

echo ""
echo "=========================================="
echo " reload-push-options Test Suite"
echo "=========================================="
echo ""

docker compose down -v 2>/dev/null || true

# Initial config is now baked into the image (server.conf.default)
# and restored on container start by server-entrypoint.sh

info "Building and starting containers..."
docker compose build
docker compose up -d --wait
wait_for_clients

# Test 1: No update-clients - routes must NOT change (still have initial routes, not the new 192.168.30.0)
run_test "Test 1: No update-clients" client1 0 \
    'push "route 192.168.10.0 255.255.255.0"
push "route 192.168.20.0 255.255.255.0"
push "route 192.168.30.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"' \
    "192\.168\.10\.0|192\.168\.20\.0" "192\.168\.30\.0"

# Test 2: Add route
run_test "Test 2: Add route" client1 1 \
    'push "route 192.168.10.0 255.255.255.0"
push "route 192.168.20.0 255.255.255.0"
push "route 192.168.30.0 255.255.255.0"
push "route 192.168.40.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"' \
    "192\.168\.40\.0" ""

# Test 3: Remove route
run_test "Test 3: Remove route" client1 1 \
    'push "route 192.168.10.0 255.255.255.0"
push "route 192.168.30.0 255.255.255.0"
push "route 192.168.40.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"' \
    "" "192\.168\.20\.0"

# Test 4: Remove all routes
run_test "Test 4: Remove all routes" client1 1 \
    'push "dhcp-option DNS 8.8.8.8"' \
    "" "192\.168\."

# Test 5: Add new routes
run_test "Test 5: New routes" client1 1 \
    'push "route 172.16.0.0 255.255.0.0"
push "route 172.17.0.0 255.255.0.0"
push "dhcp-option DNS 1.1.1.1"' \
    "172\.(16|17)\.0\.0" ""

# Test 6: Mixed - remove 172.16, keep 172.17, add 10.10
run_test "Test 6: Mixed changes" client1 1 \
    'push "route 172.17.0.0 255.255.0.0"
push "route 10.10.0.0 255.255.0.0"
push "dhcp-option DNS 1.1.1.1"' \
    "172\.17\.0\.0|10\.10\.0\.0" "172\.16\.0\.0"

# Test 7: Reconnected client gets current config
echo ""
echo "--- Test 7: Reconnect ---"
info "Updating config and restarting client2"

update_server_config 'push "route 172.17.0.0 255.255.0.0"
push "route 10.10.0.0 255.255.0.0"
push "route 192.168.100.0 255.255.255.0"
push "route 192.168.200.0 255.255.255.0"
push "dhcp-option DNS 1.1.1.1"'

docker compose restart client2
sleep 5

run_test "Test 7: Reconnect" client2 skip \
    'push "route 172.17.0.0 255.255.0.0"
push "route 10.10.0.0 255.255.0.0"
push "route 192.168.100.0 255.255.255.0"
push "route 192.168.200.0 255.255.255.0"
push "dhcp-option DNS 1.1.1.1"' \
    "172\.17\.0\.0|10\.10\.0\.0|192\.168\.100\.0|192\.168\.200\.0" ""

# Test 8: Stress test with 500 routes
echo ""
echo "--- Test 8: 500 routes stress test ---"
info "Generating config with 500 routes..."

# Generate 500 routes: 10.{1-250}.{0,128}.0/25
routes_config=""
for i in $(seq 1 250); do
    routes_config+="push \"route 10.$i.0.0 255.255.128.0\"
"
    routes_config+="push \"route 10.$i.128.0 255.255.128.0\"
"
done
routes_config+='push "dhcp-option DNS 8.8.8.8"'

update_server_config "$routes_config"

log_lines=$(get_client_log_lines client1)
result=$(mgmt "reload-push-options update-clients")
echo "Management response: $result"

if ! echo "$result" | grep -q "SUCCESS"; then
    fail "Test 8: 500 routes - command failed"
fi
pass "Test 8: 500 routes - command succeeded"

wait_for_client_ready client1 "$log_lines"

routes=$(get_client_routes client1)
route_count=$(echo "$routes" | grep -c "^10\." || true)
info "Route count: $route_count"

if [ "$route_count" -ge 450 ]; then
    pass "Test 8: 500 routes - received $route_count routes"
else
    fail "Test 8: 500 routes - expected ~500 routes, got $route_count"
fi

echo ""
echo "=========================================="
echo -e "${GREEN}All tests completed!${NC}"
echo "=========================================="
