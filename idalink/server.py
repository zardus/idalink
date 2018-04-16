#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus
#                     Ruoyu Wang aka. fish
#                     Andrew Dutcher aka. rhelmot
#                     Kevin Borgolte aka. cao

from __future__ import print_function

import threading

# idc is just within IDA, so make pylint stop complaining
import idc      # pylint: disable=F0401

from rpyc.core import SlaveService
from rpyc.utils.server import OneShotServer, ThreadedServer


if __name__ == '__main__':
    print('Received arguments: {}'.format(idc.ARGV))

    port = int(idc.ARGV[1]) if idc.ARGV[1:] else 18861
    mode = idc.ARGV[2] if idc.ARGV[2:] else 'oneshot'

    # :note: For speed, we don't want to idc.Wait() here,
    #        but you might want to call it in your code
    #        to make sure that autoanalysis has finished.

    if mode == 'threaded':
        ThreadedServer(SlaveService, port=port).start()
    else:
        OneShotServer(SlaveService, port=port).start()
        idc.Exit(0)
