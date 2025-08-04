#!/bin/sh
#
# Run this stress test as root to avoid sudo authorization from timing out.

ITERATIONS="${1:-100}"

. ./t_server_null_default.rc

export pid_files=""
for SUF in $TEST_SERVER_LIST
do
    eval server_name=\"\$SERVER_NAME_$SUF\"
    pid_files="${pid_files} ./${server_name}.pid"
done

LOG_BASEDIR="make-check"
mkdir -p "${LOG_BASEDIR}"

count=0
while [ $count -lt $ITERATIONS ]; do
    count=$(( count + 1 ))
    make check TESTS=t_server_null.sh SUBDIRS= > /dev/null 2>&1
    retval=$?

    echo "Iteration ${count}: return value ${retval}" >> "${LOG_BASEDIR}/make-check.log"
    if [ $retval -ne 0 ]; then
	DIR="${LOG_BASEDIR}/make-check-${count}"
        mkdir -p "${DIR}"
        cp t_server_null*.log "${DIR}/"
        cp test-suite.log "${DIR}/"
        ps aux|grep openvpn|grep -vE '(suppress|grep)' > "${DIR}/psaux"
    fi
done
