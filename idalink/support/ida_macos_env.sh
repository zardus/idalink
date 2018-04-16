#!/bin/bash

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus

export TERM=xterm
export _DYLD_INSERT_LIBRARIES=$VIRTUAL_ENV/.Python

IDA="$1"
shift
DYLD_INSERT_LIBRARIES=$_DYLD_INSERT_LIBRARIES "$IDA" "$@"
