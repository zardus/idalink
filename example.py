#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

from idalink import idalink

# We want debug messages for now
import logging
idalink_log = logging.getLogger('idalink')
idalink_log.addHandler(logging.StreamHandler())
idalink_log.setLevel(logging.DEBUG)

# Let's do some testing with idalink!
with idalink('./tests/bash', 'idal64') as ida:
    # use idc
    s = ida.idc.ScreenEA()
    print('Default ScreenEA is {:x}'.format(s))

    # use idautils
    print('All segments')
    for s in ida.idautils.Segments():
        print(' - Segment at {:x} is named {}'.format(s, ida.idc.SegName(s)))

    # use idaapi
    print('First byte for each function')
    for i, s in enumerate(ida.idautils.Functions()):
        print(' - Byte at {:x} is {:02x}'.format(s, ida.idaapi.get_byte(s)))

    # access IDA memory in a dict way
    print('Accessing memory directly')
    functions = next(ida.idautils.Functions())
    print(' - Byte at {:x} is {}'.format(s, ida.memory[s]))
