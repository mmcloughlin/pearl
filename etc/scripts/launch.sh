#!/bin/bash -ex

LOGDIR=logs

port=$((3000 + RANDOM % 5000))
nick=$(printf "pearl%04x" $RANDOM)
logfile=${LOGDIR}/${nick}.json

mkdir -p ${LOGDIR}
make install-race
pearl serve -n ${nick} -p ${port} -l ${logfile}
