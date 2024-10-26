#!/bin/sh
#
TSERVER_NULL_SKIP_RC="${TSERVER_NULL_SKIP_RC:-77}"

if ! [ -r "./t_server_null.rc" ] ; then
    echo "${0}: cannot find './t_server_null.rc. SKIPPING TEST.'" >&2
    exit "${TSERVER_NULL_SKIP_RC}"
fi

. ./t_server_null.rc

if KILL_EXEC=$(which kill); then
    export KILL_EXEC
else
    echo "${0}: kill not found in \$PATH" >&2
    exit "${TSERVER_NULL_SKIP_RC}"
fi

# Ensure PREFER_KSU is in a known state
PREFER_KSU="${PREFER_KSU:-0}"

# make sure we have permissions to run ifconfig/route from OpenVPN
# can't use "id -u" here - doesn't work on Solaris
ID=$(id)
if expr "$ID" : "uid=0" >/dev/null
then :
else
    if [ "${PREFER_KSU}" -eq 1 ];
    then
        # Check if we have a valid kerberos ticket
        if klist -l 1>/dev/null 2>/dev/null; then
            RUN_SUDO="ksu -q -e"
        else
            # No kerberos ticket found, skip ksu and fallback to RUN_SUDO
            PREFER_KSU=0
            echo "${0}: No Kerberos ticket available.  Will not use ksu."
        fi
    fi

    if [ -z "$RUN_SUDO" ]
    then
        echo "${0}: this test must run be as root, or RUN_SUDO=... " >&2
        echo "      must be set correctly in 't_server_null.rc'. SKIP." >&2
        exit "${TSERVER_NULL_SKIP_RC}"
    else
	# Run a no-op command with privilege escalation (e.g. sudo) so that
	# we (hopefully) do not have to ask the users password during the test.
	if $RUN_SUDO "${KILL_EXEC}" -0 $$
	then
	    echo "${0}: $RUN_SUDO $KILL_EXEC -0 succeeded, good."
	else
	    echo "${0}: $RUN_SUDO $KILL_EXEC -0 failed, cannot go on. SKIP." >&2
	    exit "${TSERVER_NULL_SKIP_RC}"
	fi
    fi
fi

srcdir="${srcdir:-.}"
export t_server_null_logdir=t_server_null-`hostname`-`date +%Y%m%d-%H%M%S`

# Create directory for server and client logs
mkdir $t_server_null_logdir

"${srcdir}/t_server_null_server.sh" &
T_SERVER_NULL_SERVER_PID=$!

"${srcdir}/t_server_null_client.sh"
retval=$?

# When running make jobs in parallel ("make -j<x> check") we need to ensure
# that this script does not exit before all --dev null servers are dead and
# their network interfaces are gone. Otherwise t_client.sh will fail because
# pre and post ifconfig output does not match.
wait $T_SERVER_NULL_SERVER_PID

if [ $? -ne 0 ]; then
    exit 1
else
    exit $retval
fi
