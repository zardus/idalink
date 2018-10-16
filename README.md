# idalink

idalink arose of the need to easily use IDA's API for analysis without wanting
to be stuck in the IDA interface. It's rather hackish still and and we provide
no warranty of any kind (express or implied), but we are doing our best to fix
any issues you find. Pull requests are -of course- also encouraged!

idalink works by spawning an IDA CLI session in the background (in a detached
screen session), and connects to it using RPyC.

## Requirements

idalink requires the following:

- Python 2 (ida does not support python 3)
- IDA Pro >= 7.0
- libssl0.9.8:i386 (for IDA's Python version)

idalink uses:
- rpyc in your Python environment outside of IDA
- rpyc in your IDA Python environment.

## Usage

To use idalink, put it in a place where you can import it and do, in any python
session (ie, outside of IDA):

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from idalink import IDALink

# We want debug messages for now
import logging
logging.basicConfig()
logging.getLogger('idalink').setLevel('DEBUG')

# Let's do some testing with idalink!
with IDALink("idat64", "./tests/bash") as ida:
    # use idc
    s = ida.idc.ScreenEA()
    print("Default ScreenEA is {:x}".format(s))

    # use idautils
    print("All segments")
    for s in ida.idautils.Segments():
        print(" - Segment at {:x} is named {}".format(s, ida.idc.SegName(s)))

    # use idaapi
    print("First byte for each function")
    for i, s in enumerate(ida.idautils.Functions()):
        print(" - Byte at {:x} is {:02x}".format(s, ida.idaapi.get_byte(s)))

    # access IDA memory in a dict way
    print("Accessing memory directly")
    functions = next(ida.idautils.Functions())
    print(" - Byte at {:x} is {}".format(s, ida.memory[s]))
```

And that's that. Basically, you get access to the IDA API from outside of IDA.
Good stuff.

## Issues

- A random port between 40000 and 49999 is chosen for communication, with no
  error-checking for failed IDA startups or if the port is already in use.
- IDA-backed memory is not really tested, and uses Heads for getting the
  "mapped" list, which is slow and incomplete
