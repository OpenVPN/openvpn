#!/usr/bin/env bash

IFACE="ovpn-dummy0"
UNIT_TEST="./unit_tests/openvpn/networking_testdriver"
LAST_AUTO_TEST=7
LAST_TEST=8

srcdir="${srcdir:-.}"
top_builddir="${top_builddir:-..}"
openvpn="${openvpn:-${top_builddir}/src/openvpn/openvpn}"


# bail out right away on non-linux. NetLink (the object of this test) is only
# used on Linux, therefore testing other platform is not needed.
#
# Note: statements in the rest of the script may not even pass syntax check on
# solaris/bsd. It uses /bin/bash
if [ "$(uname -s)" != "Linux" ]; then
    echo "$0: this test runs only on Linux. SKIPPING TEST."
    exit 77
fi

# Commands used to retrieve the network state.
# State is retrieved after running sitnl and after running
# iproute commands. The two are then compared and expected to be equal.
typeset -a GET_STATE
GET_STATE[0]="ip link show dev $IFACE | sed 's/^[0-9]\+: //'"
GET_STATE[1]="ip addr show dev $IFACE | sed 's/^[0-9]\+: //'"
GET_STATE[2]="ip route show dev $IFACE"
GET_STATE[3]="ip -6 route show dev $IFACE"

LAST_STATE=$((${#GET_STATE[@]} - 1))

reload_dummy()
{
    $RUN_SUDO ip link del $IFACE
    $RUN_SUDO ip link add $IFACE address 00:11:22:33:44:55 type dummy
    $RUN_SUDO ip link set dev $IFACE state up

    if [ $? -ne 0 ]; then
        echo "can't create interface $IFACE"
        exit 1
    fi
}

run_test()
{
    # run all test cases from 0 to $1 in sequence
    CMD=
    for k in $(seq 0 $1); do
        # the unit-test prints to stdout the iproute command corresponding
        # to the sitnl operation being executed.
        # Format is "CMD: <commandhere>"
        OUT=$($RUN_SUDO $UNIT_TEST $k $IFACE)
        # ensure unit test worked properly
        if [ $? -ne 0 ]; then
            echo "unit-test $k errored out:"
            echo "$OUT"
            exit 1
        fi

        NEW=$(echo "$OUT" | sed -n 's/CMD: //p')
        CMD="$CMD $RUN_SUDO $NEW ;"
    done

    # collect state for later comparison
    for k in $(seq 0 $LAST_STATE); do
        STATE_TEST[$k]="$(eval ${GET_STATE[$k]})"
    done
}


## execution starts here

# t_client.rc required only for RUN_SUDO definition
if [ -r "${top_builddir}"/t_client.rc ]; then
    . "${top_builddir}"/t_client.rc
elif [ -r "${srcdir}"/t_client.rc ]; then
    . "${srcdir}"/t_client.rc
fi

if [ ! -x "$openvpn" ]; then
    echo "no (executable) openvpn binary in current build tree. FAIL." >&2
    exit 1
fi

if [ ! -x "$UNIT_TEST" ]; then
    echo "no test_networking driver available. SKIPPING TEST." >&2
    exit 77
fi


# Ensure PREFER_KSU is in a known state
PREFER_KSU="${PREFER_KSU:-0}"

# make sure we have permissions to run the networking unit-test
ID=`id`
if expr "$ID" : "uid=0" >/dev/null
then :
else
    if [ "${PREFER_KSU}" -eq 1 ];
    then
        # Check if we have a valid kerberos ticket
        klist -l 1>/dev/null 2>/dev/null
        if [ $? -ne 0 ];
        then
            # No kerberos ticket found, skip ksu and fallback to RUN_SUDO
            PREFER_KSU=0
            echo "$0: No Kerberos ticket available.  Will not use ksu."
        else
            RUN_SUDO="ksu -q -e"
        fi
    fi

    if [ -z "$RUN_SUDO" ]
    then
        echo "$0: no RUN_SUDO=... in t_client.rc or environment, defaulting to 'sudo'." >&2
        echo "      if that does not work, set RUN_SUDO= correctly for your system." >&2
        RUN_SUDO="sudo"
    fi

    # check that we can run the unit-test binary with sudo
    if $RUN_SUDO $UNIT_TEST test
    then
        echo "$0: $RUN_SUDO $UNIT_TEST succeeded, good."
    else
        echo "$0: $RUN_SUDO $UNIT_TEST failed, cannot go on. SKIP." >&2
        exit 77
    fi
fi

for i in $(seq 0 $LAST_AUTO_TEST); do
    # reload dummy module to cleanup state
    reload_dummy
    typeset -a STATE_TEST
    run_test $i

    # reload dummy module to cleanup state before running iproute commands
    reload_dummy

    # CMD has been set by the unit test
    eval $CMD
    if [ $? -ne 0 ]; then
        echo "error while executing:"
        echo "$CMD"
        exit 1
    fi

    # collect state after running manual ip command
    for k in $(seq 0 $LAST_STATE); do
        STATE_IP[$k]="$(eval ${GET_STATE[$k]})"
    done

    # ensure states after running unit test matches the one after running
    # manual iproute commands
    for j in $(seq 0 $LAST_STATE); do
        if [ "${STATE_TEST[$j]}" != "${STATE_IP[$j]}" ]; then
            echo "state $j mismatching after '$CMD'"
            echo "after unit-test:"
            echo "${STATE_TEST[$j]}"
            echo "after iproute command:"
            echo "${STATE_IP[$j]}"
            exit 1
        fi
    done
    echo "Test $i: OK"
done

# remove interface for good
$RUN_SUDO ip link del $IFACE

for i in $(seq $(($LAST_AUTO_TEST + 1)) ${LAST_TEST}); do
    $RUN_SUDO $UNIT_TEST $i
    if [ $? -ne 0 ]; then
        echo "unit-test $i errored out"
        exit 1
    fi

    echo "Test $i: OK"
done

exit 0
