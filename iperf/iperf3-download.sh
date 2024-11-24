#!/bin/bash

program_name=''
OMIT_SECS=3
# RUN_SECS=6
RUN_SECS=5
OUTPUT_DIR="/etc/vector/sample_output"

if [[ -z $REMOTE_USER ]]; then
    echo "ERROR: REMOTE_USER is required";
fi
if [[ -z $REMOTE_HOST ]]; then
    echo "ERROR: REMOTE_HOST is required";
fi
if [[ -z $ID_RSA_PATH ]]; then
    echo "ERROR: ID_RSA_PATH is required";
fi

# http://www.gnu.org/software/bash/manual/bashref.html#Conditional-Constructs
re="(\.\/)?([^\.]+)\.sh"
if [[ $0 =~ $re ]]; then 
    program_name="${BASH_REMATCH[2]}";
fi

ssh -i $ID_RSA_PATH "${REMOTE_USER}@${REMOTE_HOST}" -C "iperf3 --server --json --one-off --daemon --timestamps"
iperf3 --json --client $REMOTE_HOST --zerocopy --reverse --omit $OMIT_SECS --time $RUN_SECS --get-server-output |  tee "${OUTPUT_DIR}`date +"%Y-%m-%d_%H%M%S_%Z"`_${program_name}.json"
