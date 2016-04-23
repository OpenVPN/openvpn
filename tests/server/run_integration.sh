#!/usr/bin/env bash

#
# Configuration
#


# Path is relative to the pth of the folder containing Vagrantfile
TEST_PROGRAM=./launch_t_client.sh

# set to --force to just kill the VM power after the test.
# keep empty for gracefull shutdoen
FORCE_VM_SHUTDOWN=--force


#
# t_client.rc
#

# Make sure we trigger sudo password before starting the background processed
# they mess up stdin/stdout and make sudo print the password.
# Does _not_ fail without sudo/root. This is left to t_client.sh
try_sudo_command_or_root() {
    ID=`id`
    if expr "$ID" : "uid=0" >/dev/null ; then
        print_log I "running as root. sudo not needed"
    else
        srcdir="${srcdir:-..}"
        top_builddir="${top_builddir:-../..}"

        if [ -r "${top_builddir}"/t_client.rc ] ; then
            print_log I "sourcing ${top_builddir}/t_client.rc"
            . "${top_builddir}"/t_client.rc
        elif [ -r "${srcdir}"/t_client.rc ] ; then
            print_log I "sourcing ${srcdir}/t_client.rc"
            . "${srcdir}"/t_client.rc
        else
            print_log Iw "t_client.sh neither found at '${top_builddir}/t_client.rc' nor '"${srcdir}"/t_client.rc'"
        fi

        if [ -z "$RUN_SUDO" ] ; then
            print_log Iw "RUN_SUDO not defined and not running as root. t_client.sh wil propably fail."
        else
            # We have to use sudo. Make sure that we (hopefully) do not have
            # to ask the users password during the test. This is done to
            # prevent timing issues, e.g. when the waits for openvpn to start.
            "$RUN_SUDO" \true || print_log Iw "'$RUN_SUDO' failed"
        fi
    fi
}



#
# Implementation
#


if [ $# -ne 1 ]; then
    echo $0 vm_folder
    exit -1
fi


VM_FOLDER=$1
if [ ! -d  "$VM_FOLDER" ]; then
    echo $0 vm_folder
    echo "-- '${VM_FOLDER}' is no directory"
    exit -1
fi


# result 99: test not run bc. server could not be started
test_result=99

start_vm() {
  cd "${VM_FOLDER}"
  vagrant halt
  vagrant up
  vagrant ssh -c '/scripts/sync_codebase.sh && /scripts/compile.sh'
}

# Start t_client when the server emitted a line containing ${START_TEST_ON}
START_TEST_ON="Initialization Sequence Completed"

# $1 : Source/Color schema: _S_erver, _C_lient, _I_ntegration (this script
#         Iw: Warning
# $2 : message
colorize() {
  local schema="$1"
  local msg="$2"

  local BLACK=$(tput setaf 0)
  local RED=$(tput setaf 1)
  local GREEN=$(tput setaf 2)
  local YELLOW=$(tput setaf 3)
  local LIME_YELLOW=$(tput setaf 190)
  local POWDER_BLUE=$(tput setaf 153)
  local BLUE=$(tput setaf 4)
  local MAGENTA=$(tput setaf 5)
  local CYAN=$(tput setaf 6)
  local WHITE=$(tput setaf 7)
  local BRIGHT=$(tput bold)
  local NORMAL=$(tput sgr0)
  local BLINK=$(tput blink)
  local REVERSE=$(tput smso)
  local UNDERLINE=$(tput smul)

  local ERROR="$RED"

  local color=""

  case "$schema" in
    "S")
      color="${POWDER_BLUE}"
    ;;
    "C")
      color="${YELLOW}"
    ;;
    "I")
      color="${GREEN}"
    ;;
    "Iw")
      color="${BRIGHT}${RED}"
    ;;
    *)
      color="${NORMAL}"
    ;;
  esac

  msg="${color}${msg}${NORMAL}"

  msg=${msg/FATAL/${ERROR}FATAL${color}}
  msg=${msg/FAIL/${ERROR}FAIL${color}}
  echo $msg
}

# $1 : Source/Color schema: _S_erver, _C_lient, _I_ntegration (this script)
# $2 : message (one line)
print_log() {
  local src="$1"
  local line="$2"

  # Remove non-ascii. Esp. remove CR/LF because they break the processing logic
  # Remove leading and trailing spaces
  local sanitized=$(echo "$line" | tr -cd '\40-\176' \
                                 | sed -e 's/^[ ]+//' -e 's/[ ]+$//')
  sanitized=$(colorize $src "$sanitized")

  printf "%s:\t%s\n" "$src" "$sanitized"
}



# Run the test command defined in $TEST_PROGRAM and halt the VM afterwards
run_test() {
  echo Starting Client

  #Important: run 'test | format' so that the exit code of test is not lost
  $TEST_PROGRAM 2>&1 | while read client_line
  do
    print_log "C" "$client_line"
  done

  local result=${PIPESTATUS[0]}
  vagrant halt ${FORCE_VM_SHUTDOWN}

  return $result
}

try_sudo_command_or_root
start_vm

while read server_line
do
  # At least on MacOS this is needed (without it the code only prints LF,
  # but no CR)
  reset -I

  print_log "S"  "$server_line"

  if [[ "$server_line" == *$START_TEST_ON* ]] ; then
      run_test &
  fi
done < <(vagrant ssh -c 'sudo /scripts/start_server.sh' &)

echo "Waiting for all jobs to terminate ...."

wait %run_test
test_result=$?
wait

exit $test_result
