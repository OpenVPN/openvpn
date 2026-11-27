#!/bin/sh
#
# t_short_write.sh - regression test for TCP short-write stream corruption
#
# An LD_PRELOAD shim halves every data-channel send().  If the send path does
# not retry, forward.c logs a truncation warning and the stream is corrupted.
#
# Exit 0  (PASS): no truncation — short writes handled correctly
# Exit 1  (FAIL): truncation warning found — bug is present
# Exit 77 (SKIP): prerequisites missing or unsupported platform
#

set -e

top_srcdir="${top_srcdir:-..}"
top_builddir="${top_builddir:-..}"
openvpn="${openvpn:-${top_builddir}/src/openvpn/openvpn}"
shim="${shim:-$(cd "${top_builddir}/tests" && pwd)/.libs/short_write_shim.so}"

# LD_PRELOAD interposition requires a Linux ELF dynamic linker.
case $(uname -s) in
    Linux) ;;
    *) echo "$0: LD_PRELOAD shim requires Linux. SKIP." >&2; exit 77 ;;
esac

test -x "${openvpn}" || { echo "$0: openvpn binary not found. SKIP." >&2;      exit 77; }
test -f "${shim}"    || { echo "$0: short_write_shim.so not built. SKIP." >&2; exit 77; }

# Port chosen to avoid the loopback-{server,client} sample configs (16000/16001).
SRV_PORT="${SRV_PORT:-16002}"

root="${top_srcdir}/sample"
WORKDIR="$(pwd)"
SRV_LOG="${WORKDIR}/sw_srv_$$.log"
CLI_LOG="${WORKDIR}/sw_cli_$$.log"
SRV_PID="${WORKDIR}/sw_srv_$$.pid"

cleanup() {
    if [ -n "${CLI_PID}" ]; then
        kill "${CLI_PID}" 2>/dev/null || true
    fi
    if [ -f "${SRV_PID}" ]; then
        pid=$(cat "${SRV_PID}" 2>/dev/null)
        [ -n "${pid}" ] && kill "${pid}" 2>/dev/null || true
    fi
    rm -f "${SRV_LOG}" "${CLI_LOG}" "${SRV_PID}"
}

CLI_PID=""

trap "cleanup; trap 0; exit 77" 1 2 15
trap "cleanup; exit 1"          0 3

# Poll $CLI_LOG for regex $1 for up to $2 seconds.
wait_for() {
    _pat=$1; _tries=$2
    while [ "${_tries}" -gt 0 ]; do
        grep -qE "${_pat}" "${CLI_LOG}" 2>/dev/null && return 0
        [ -n "${CLI_PID}" ] && ! kill -0 "${CLI_PID}" 2>/dev/null && return 1
        sleep 1
        _tries=$((_tries - 1))
    done
    return 1
}

success=0
for i in 1 2 3; do
    set +e

    "${openvpn}" \
        --cd "${root}" --dev null --proto tcp-server \
        --local 127.0.0.1 --lport "${SRV_PORT}" \
        --tls-server --dh none \
        --ca  sample-keys/ca.crt \
        --key sample-keys/server.key \
        --cert sample-keys/server.crt \
        --cipher AES-256-GCM --verb 3 \
        --writepid "${SRV_PID}" --log "${SRV_LOG}" --daemon

    j=0
    while [ $j -lt 10 ] && [ ! -s "${SRV_PID}" ]; do
        sleep 1; j=$((j+1))
    done

    if [ ! -s "${SRV_PID}" ]; then
        if grep -q 'TCP/UDP: Socket bind failed on local address.*in use' \
                "${SRV_LOG}" 2>/dev/null; then
            echo "$0: port ${SRV_PORT} in use, retrying in 10 s" >&2
            rm -f "${SRV_PID}" "${SRV_LOG}"
            sleep 10
            continue
        fi
        echo "$0: server did not start" >&2
        cat "${SRV_LOG}" >&2
        exit 1
    fi

    # The client never exits on its own: bug present → endless reconnect loop;
    # bug fixed → healthy tunnel forever.  Poll the log and kill when done.
    rm -f "${CLI_LOG}"
    LD_PRELOAD="${shim}" \
    "${openvpn}" \
        --cd "${root}" --dev null --proto tcp-client \
        --remote 127.0.0.1 "${SRV_PORT}" \
        --tls-client --remote-cert-tls server \
        --ca  sample-keys/ca.crt \
        --key sample-keys/client.key \
        --cert sample-keys/client.crt \
        --cipher AES-256-GCM \
        --ping 1 --ping-exit 30 \
        --verb 3 --log "${CLI_LOG}" &
    CLI_PID=$!

    if ! wait_for "P2P mode NCP negotiation result" 15; then
        echo "$0: tunnel did not establish, retrying" >&2
        kill "${CLI_PID}" 2>/dev/null; wait "${CLI_PID}" 2>/dev/null
        CLI_PID=""
        kill "$(cat ${SRV_PID})" 2>/dev/null || true
        rm -f "${SRV_PID}" "${SRV_LOG}" "${CLI_LOG}"
        continue
    fi

    set -e
    success=1
    break
done

if [ $success -ne 1 ]; then
    echo "$0: could not establish a tunnel after 3 attempts. SKIP." >&2
    trap 0; cleanup; exit 77
fi

# Tunnel is up.  The first ping (~1 s) triggers the truncation warning if the
# bug is present.  Wait a few ping cycles for it to surface.
set +e
wait_for "TCP/UDP packet was truncated/expanded on write" 5
set -e

kill "${CLI_PID}" 2>/dev/null || true
wait "${CLI_PID}" 2>/dev/null || true
CLI_PID=""

ec=0
if grep -q "TCP/UDP packet was truncated/expanded on write" "${CLI_LOG}"; then
    echo "$0: FAIL: short-write caused stream truncation" >&2
    ec=1
else
    echo "$0: PASS: no truncation detected" >&2
fi

cleanup
trap 0
exit $ec
