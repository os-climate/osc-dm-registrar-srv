#!/bin/bash

#####
#
# venv.sh - Create virtual environment for the project
#
# Author: Eric Broda, eric.broda@brodagroupsoftware.com, August 17, 2023
#
#####

if [ -z ${ROOT_DIR+x} ] ; then
    echo "Environment variables have not been set.  Run 'source bin/environment.sh'"
    exit 1
fi

function showHelp {
    echo " "
    echo "ERROR: $1"
    echo " "
    echo "Usage:"
    echo " "
    echo "    venv.sh "
    echo " "
}

# Create the virtual environment in a directory called
cd $PROJECT_DIR
NAME="venv"
python3 -m venv $NAME
