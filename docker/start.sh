#!/bin/bash

if [ "$*" == "/bin/bash" ]; then
    echo "nothing to do"
else
    /bin/bash -l -c "$*"
fi