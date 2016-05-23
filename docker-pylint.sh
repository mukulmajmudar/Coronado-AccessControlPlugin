#!/bin/bash
set -x
docker build -t $USER/coronado-accesscontrolplugin .
docker run --rm --entrypoint=pylint $USER/coronado-accesscontrolplugin AccessControlPlugin
