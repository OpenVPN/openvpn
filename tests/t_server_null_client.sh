#!/bin/sh

should_run_test() {
    test_name="$1"

    if echo "$test_name"|grep -q _lwip; then
        if [ "$has_lwipovpn" = "no" ]; then
            return 1
        fi
    fi

    return 0
}

launch_client() {
    test_name=$1
    log="${test_name}.log"
    pid="${test_name}.pid"
    client_exec=$2
    client_conf=$3

    # Ensure that old log and pid files are gone
    rm -f "${log}" "${pid}"

    "${client_exec}" \
        $client_conf \
        --writepid "${pid}" \
        --setenv pid "$pid" \
        --setenv test_name "$test_name" \
        --log "${t_server_null_logdir}/${log}" &
}

ping_and_kill() {
    if fping -q -c 5 $1; then
        echo "PASS: fping lwipovpn client $target"
    else
        echo "FAIL: fping lwipovpn client $target"

        # This function runs multiple times in parallel in subshells. That
        # makes it hard to implement "fail the test suite if any single fping
        # test fails" using exit codes or variables given the limitations of
        # "wait".  Therefore we use a marker file here, which solves the
        # problem trivially.
        touch ./lwip_failed
    fi
    kill -15 $2
}

ping_lwip_clients() {
    if [ "$has_lwipovpn" = "yes" ]; then
        lwip_client_count=$(echo "$lwip_test_names"|wc -w|tr -d " ")
    else
        lwip_client_count=0
    fi

    if [ $lwip_client_count -eq 0 ]; then
        return 0
    fi

    count=0
    maxcount=10
    while [ $count -le $maxcount ]; do
        lwip_client_ips=$(cat ./*.lwip 2>/dev/null|wc -l)
        if [ $lwip_client_ips -lt $lwip_client_count ]; then
            echo "Waiting for LWIP clients to start up ($count/$maxcount)"
            count=$(( count + 1))
            sleep 1
        else
            echo "$lwip_client_ips/$lwip_client_count LWIP clients up"
            break
        fi
    done

    wait_pids=""
    for line in $(cat ./*.lwip 2>/dev/null); do
        target_ip=$(echo $line|cut -d "," -f 1)
        client_pid=$(echo $line|cut -d "," -f 2)
        ping_and_kill $target_ip $client_pid &
        wait_pids="$wait_pids $!"
    done

    wait $wait_pids

    test -e ./lwip_failed && return 1 || return 0
}

wait_for_results() {
    tests_running="yes"

    # Wait a bit to allow an OpenVPN client process to create a pidfile to
    # prevent exiting too early
    sleep 1

    while [ "${tests_running}" = "yes" ]; do
        tests_running="no"
        for t in $test_names; do
            if [ -f "${t}.pid" ]; then
                tests_running="yes"
            fi
        done

        if [ "${tests_running}" = "yes" ]; then
            echo "Clients still running"
            sleep 1
        fi
    done
}

get_client_test_result() {
    test_name=$1
    should_pass=$2
    log="${test_name}.log"

    grep "Initialization Sequence Completed" "${t_server_null_logdir}/${log}" > /dev/null
    exit_code=$?

    if [ $exit_code -eq 0 ] && [ "${should_pass}" = "yes" ]; then
        echo "PASS ${test_name}"
    elif [ $exit_code -eq 1 ] && [ "${should_pass}" = "no" ]; then
        echo "PASS ${test_name} (test failure)"
    elif [ $exit_code -eq 0 ] && [ "${should_pass}" = "no" ]; then
        echo "FAIL ${test_name} (test failure)"
        cat "${t_server_null_logdir}/${log}"
        retval=1
    elif [ $exit_code -eq 1 ] && [ "${should_pass}" = "yes" ]; then
        echo "FAIL ${test_name}"
        cat "${t_server_null_logdir}/${log}"
        retval=1
    fi
}

# Load basic/default tests
. ${srcdir}/t_server_null_default.rc || exit 1

# Load additional local tests, if any
test -r ./t_server_null.rc && . ./t_server_null.rc

# Return value for the entire test suite. Gets set to 1 if any test fails.
export retval=0

# Wait until servers are up. This check is based on the presence of processes
# matching the PIDs in each servers PID files
count=0
server_max_wait=15
while [ $count -lt $server_max_wait ]; do
    servers_up=0
    server_count=$(echo "$TEST_SERVER_LIST"|wc -w|tr -d " ")

    # We need to trim single-quotes because some shells return quoted values
    # and some don't. Using "set -o posix" which would resolve this problem is
    # not supported in all shells.
    #
    # While inactive server configurations may get checked they won't increase
    # the active server count as the processes won't be running.
    for i in $(set|grep 'SERVER_NAME_'|cut -d "=" -f 2|tr -d "[\']"); do
        server_pid=$(cat "$i.pid" 2> /dev/null)
        if [ -z "$server_pid" ] ; then
            continue
        fi
        if $RUN_SUDO kill -0 $server_pid > /dev/null 2>&1; then
            servers_up=$(( $servers_up + 1 ))
        fi
    done

    echo "OpenVPN test servers up: ${servers_up}/${server_count}"

    if [ $servers_up -ge $server_count ]; then
        retval=0
        break
    else
        count=$(( count + 1))
        sleep 1
    fi

    if [ $count -eq $server_max_wait ]; then
        retval=1
        exit $retval
    fi
done

# Check for presence of the lwipovpn executable
if test -r "$LWIPOVPN_PATH"; then
    has_lwipovpn="yes"
else
    has_lwipovpn="no"
    echo "WARNING: lwipovpn executable is missing: lwip tests will be skipped"
fi

# Remove existing LWIP client IP files. This is to avoid pinging non-existent
# IP addresses when tests are disabled.
rm -f ./*.lwip
rm -f ./lwip_failed

# Wait a while to let server processes to settle down
sleep 1

# Launch OpenVPN clients. While at it, construct a list of test names. The list
# is used later to determine when all OpenVPN clients have exited and it is
# safe to check the test results.
test_names=""
lwip_test_names=""
for SUF in $TEST_RUN_LIST
do
    eval test_name=\"\$TEST_NAME_$SUF\"
    eval client_exec=\"\$CLIENT_EXEC_$SUF\"
    eval client_conf=\"\$CLIENT_CONF_$SUF\"

    test_names="${test_names} ${test_name}"

    if echo "$test_name"|grep -q _lwip; then
        lwip_test_names="${lwip_test_names} ${test_name}"
    fi

    if should_run_test "$test_name"; then
        (launch_client "${test_name}" "${client_exec}" "${client_conf}")
    fi
done

ping_lwip_clients
retval=$?


# Wait until all OpenVPN clients have exited
(wait_for_results)

# Check test results
for SUF in $TEST_RUN_LIST
do
    eval test_name=\"\$TEST_NAME_$SUF\"
    eval should_pass=\"\$SHOULD_PASS_$SUF\"

    if should_run_test "$test_name"; then
        get_client_test_result "${test_name}" "${should_pass}"
    fi
done

exit $retval
