#!/bin/bash -ex

DATADIR=/tmp/pearl/nodes

port=$((3000 + RANDOM % 5000))
nick=$(printf "pearl%04x" $RANDOM)
datadir=${DATADIR}/$nick
logfile=${datadir}/log.json

mkdir -p ${datadir}
make install-race
pearl genkeys -d ${datadir}
pearl serve -n ${nick} -p ${port} -d ${datadir} -l ${logfile}
