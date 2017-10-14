#!/bin/bash -ex

cp $GOROOT/src/crypto/sha1/* .
sed -i 's/digest/Digest/g' *.go
