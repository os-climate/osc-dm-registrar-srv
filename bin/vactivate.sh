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
    echo "Usage: (NOTE: Must be executed via 'source') "
    echo " "
    echo "    source vactivate.sh"
    echo " "
}

# Check if the script is sourced
# Reference: https://superuser.com/questions/688882/how-to-test-if-a-variable-is-equal-to-a-number-in-shell
(return 0 2>/dev/null) && IS_SOURCED=1 || IS_SOURCED=0
if [[ "$IS_SOURCED" -eq 0 ]]; then
    showHelp "Must be executed via 'source' "
    exit
fi

VENV_NAME="venv"
if [[ "$OSTYPE" == "msys" ]]; then
    # For Ms/Windows
    source $PROJECT_DIR/$VENV_NAME/Scripts/activate
else
    # For Linux/MacOS
    source $PROJECT_DIR/$VENV_NAME/bin/activate
fi
echo "Activated virtual environment: $VENV_NAME"

