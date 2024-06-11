#!/usr/bin/env sh

launch_server() {
    server_name=$1
    server_exec=$2
    server_conf=$3
    log="${server_name}.log"
    status="${server_name}.status"
    pid="${server_name}.pid"

    # Ensure that old status, log and pid files are gone
    rm -f "${status}" "${log}" "${pid}"

    "${server_exec}" \
        $server_conf \
        --status "${status}" 1 \
        --log "${log}" \
        --writepid "${pid}" \
        --explicit-exit-notify 3

}

# Load base/default configuration
. "${srcdir}/t_server_null_default.rc" || exit 1

# Load local configuration, if any
test -r ./t_server_null.rc && . ./t_server_null.rc

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

for PID_FILE in $server_pid_files
do
    SERVER_PID=$(cat "${PID_FILE}")
    $KILL_EXEC "${SERVER_PID}"

    # Make sure that the server processes are truly dead before exiting
    while :
    do
        ps -p "${SERVER_PID}" > /dev/null || break
        sleep 0.2
    done
done
