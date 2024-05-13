#!/bin/bash

#####
#
# startd.sh - Start the docker environment
#
# Author: Eric Broda, eric.broda@brodagroupsoftware.com, September 24, 2023
#
# Parameters:
#   N/A
#
#####

if [ -z ${ROOT_DIR+x} ] ; then
    echo "Environment variables have not been set.  Run 'source bin/environment.sh'"
    exit 1
fi

# Show the environment
$PROJECT_DIR/bin/show.sh

usage() {
    echo " "
    echo "Error: $1"
    echo "Usage: startd.sh <INSTANCE> <CONFIG_NAME>"
    echo "  where INSTANCE is any positive number"
    echo "  and   CONFIG_NAME is the directory within '/config' containing the data product information"
    echo " "
    echo "Example: startd.sh 0 rmi"
    echo " "
}

if [ -z "$1" ]; then
    usage "Mandatory parameter INSTANCE must be provided."
    exit 1
fi

# INSTANCE must be greater than or equal to zero
if [ -z "$1" ] || ! [[ "$1" =~ ^[0-9]+$ ]] || [ "$1" -lt 0 ]; then
    usage "Invalid input, INSTANCE must be greater than or equal to zero."
    exit 1
fi
INSTANCE=$1

if [ -z "$2" ]; then
    usage "Mandatory parameter CONFIG_NAME must be provided."
    exit 1
fi
export CONFIG_NAME="$2"

export IMAGE_NAME="$PROJECT"
export HOSTNAME="$IMAGE_NAME-$INSTANCE"

BASE_PORT=24000
export PUBLIC_PORT=$(( BASE_PORT + INSTANCE ))
export PRIVATE_PORT=8000

echo "--- Docker Environment ---"
echo "IMAGE_NAME:   $IMAGE_NAME    <--- This is the docker image name"
echo "HOSTNAME:     $HOSTNAME      <--- This is the hostname running in docker"
echo "PUBLIC_PORT:  $PUBLIC_PORT   <--- This is the port to communicate with this data product"
echo "PRIVATE_PORT: $PRIVATE_PORT  <--- This is the internal port, which is not used"
echo "CONFIG_NAME:  $CONFIG_NAME   <--- This is data product configuration in the '/config' directory"
echo " "

NETWORK_NAME="localnet"
docker network create $NETWORK_NAME

compose() {
  docker-compose -f $PROJECT_DIR/docker/docker-compose.yml up
}

decompose() {
  docker-compose -f $PROJECT_DIR/docker/docker-compose.yml down
}

compose;
decompose;