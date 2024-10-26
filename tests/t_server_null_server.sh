#!/bin/sh

launch_server() {
    server_name=$1
    server_exec=$2
    server_conf=$3
    log="${t_server_null_logdir}/${server_name}.log"
    status="${server_name}.status"
    pid="${server_name}.pid"

    # Allow reading this file even umask values are strict
    touch "$log"

    if [ -z "${RUN_SUDO}" ]; then
        "${server_exec}" \
         $server_conf \
         --status "${status}" 1 \
         --log "${log}" \
         --writepid "${pid}" \
         --explicit-exit-notify 3
    else
        $RUN_SUDO "${server_exec}" \
                   $server_conf \
                   --status "${status}" 1 \
                   --log "${log}" \
                   --writepid "${pid}" \
                   --explicit-exit-notify 3
    fi
}

# Make server log files readable by normal users
umask 022

# Load base/default configuration
. "${srcdir}/t_server_null_default.rc" || exit 1

# Load local configuration, if any
test -r ./t_server_null.rc && . ./t_server_null.rc

# We can't exit immediately on the first failure as that could leave processes
# lying around.
retval=0

# Launch test servers
for SUF in $TEST_SERVER_LIST
do
    eval server_name=\"\$SERVER_NAME_$SUF\"
    eval server_exec=\"\$SERVER_EXEC_$SUF\"
    eval server_conf=\"\$SERVER_CONF_$SUF\"

    (launch_server "${server_name}" "${server_exec}" "${server_conf}")
done

# Create a list of server pid files so that servers can be killed at the end of
# the test run.
#
export server_pid_files=""
for SUF in $TEST_SERVER_LIST
do
    eval server_name=\"\$SERVER_NAME_$SUF\"
    server_pid_files="${server_pid_files} ./${server_name}.pid"
done

# Wait until clients are no more, based on the presence of their pid files.
# Based on practical testing we have to wait at least four seconds to avoid
# accidentally exiting too early.
count=0
maxcount=4
while [ $count -le $maxcount ]; do
    if ls t_server_null_client.sh*.pid > /dev/null 2>&1
    then
        count=0
        sleep 1
    else
	count=$(( count + 1))
        sleep 1
    fi
done

echo "All clients have disconnected from all servers"

# Make sure that the server processes are truly dead before exiting.  If a
# server process does not exit in 15 seconds assume it never will, move on and
# hope for the best.
echo "Waiting for servers to exit"
for PID_FILE in $server_pid_files
do
    SERVER_PID=$(cat "${PID_FILE}")

    if [ -z "$SERVER_PID" ] ; then
        echo "WARNING: could not kill server ${PID_FILE}!"
        continue
    fi

    # Attempt to kill the OpenVPN server gracefully with SIGTERM
    $RUN_SUDO $KILL_EXEC "${SERVER_PID}"

    count=0
    maxcount=75
    while [ $count -le $maxcount ]
    do
        $RUN_SUDO kill -0 "${SERVER_PID}" 2> /dev/null || break
        count=$(( count + 1))
        sleep 0.2
    done

    # If server is still up send a SIGKILL
    if [ $count -ge $maxcount ]; then
        $RUN_SUDO $KILL_EXEC -9 "${SERVER_PID}"
        SERVER_NAME=$(basename $PID_FILE|cut -d . -f 1)
        echo "ERROR: had to send SIGKILL to server ${SERVER_NAME} with pid ${SERVER_PID}!"
        echo "Tail of server log:"
        tail -n 20 "${t_server_null_logdir}/${SERVER_NAME}.log"
        retval=1
    fi
done

exit $retval
