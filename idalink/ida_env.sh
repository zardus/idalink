#!/bin/bash

# This code is GPLv3. See LICENSE file.

export TERM=xterm

IDA=$1
shift
$IDA "$@"
