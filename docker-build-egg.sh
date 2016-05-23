#!/bin/bash
set -x
docker build -t $USER/coronado-accesscontrolplugin .
mkdir -p dist
docker run --rm \
    -e USERID=$EUID \
    -v `pwd`/dist:/root/AccessControlPlugin/dist \
    $USER/coronado-accesscontrolplugin
