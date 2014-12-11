#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus
#                     Ruoyu Wang aka. fish
#                     Andrew Dutcher aka. rhelmot
#                     Kevin Borgolte aka. cao
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

import threading

# idc is just within IDA, so make pylint stop complaining
import idc      # pylint: disable=F0401

# pylint: disable=W0403
# :note: Those should be relative imports, but IDA doesn't like them.
from rpyc.core import SlaveService
from rpyc.utils.server import OneShotServer, ThreadedServer

if __name__ == "__main__":
    print "Received arguments: {}".format(idc.ARGV)

    port = int(idc.ARGV[1]) if idc.ARGV[1:] else 18861
    mode = idc.ARGV[2] if idc.ARGV[2:] else "oneshot"

    # :note: For speed, we don't want to idc.Wait() here,
    #        but you might want to call it in your code
    #        to make sure that autoanalysis has finished.

    if mode == "threaded":
        ThreadedServer(SlaveService, port=port).start()
    else:
        OneShotServer(SlaveService, port=port).start()
        idc.Exit(0)
