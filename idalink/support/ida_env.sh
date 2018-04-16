#!/bin/bash

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus

export TERM=xterm

IDA=$1
shift
$IDA "$@"
