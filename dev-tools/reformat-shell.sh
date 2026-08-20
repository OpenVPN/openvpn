#!/bin/sh
#
# Apply consistent formatting to our shell code.
# Uses shfmt: https://github.com/mvdan/sh

set -u

FORMAT_ARGS="--simplify --indent=4 --func-next-line --case-indent"
FORMAT_CMD="shfmt --list --write"

# hardcoded to --posix due to .in filename and invalid shebang
$FORMAT_CMD --posix $FORMAT_ARGS ./tests/t_client.sh.in
# handle *.sh files recursively
$FORMAT_CMD $FORMAT_ARGS ./tests ./dev-tools
