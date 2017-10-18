#!/bin/bash -ex

LOGDIR=logs

port=$((3000 + RANDOM % 5000))
nick=$(printf "bsp%04x" $RANDOM)
logfile=${LOGDIR}/${nick}.log

mkdir -p ${LOGDIR}
unbuffer go run -race cmd/pearl/main.go serve -n ${nick} -p ${port} | tee ${logfile}
