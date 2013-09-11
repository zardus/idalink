# idalink

I created idalink to be able to easily use IDA's API for analysis without being stuck in the IDA interface. It's rather hackish, but that's your problem :-)

This works by spawning ida in screen in the background, and connecting to it using RPyC.

## Requirements

idalink requires the following:

- ida
- screen
- rpyc (included in the repository, actually, because it's easier to use from within IDA that way)

## Setup

To setup idalink, replace the idal and idal64 symlinks in the idalink/ directory with symlinks to your actual idal and idal64 executables.

## Usage

To use idalink, put it in a place where you can import it and do, in any python session (ie, outside of IDA):

	import idalink

	# if you want to change the log file location
	# 	idalink.logfile = "/path/to/log/file"
	# if you don't want to deal with the idal and idal64 symlinks
	#	idalink.ida_dir = "/path/to/ida"

	# connect
	idalink.make_idalink("/path/to/binary/file")

	# use idc
	print "Default ScreenEA is %x" % idalink.idc.ScreenEA()

	# use idautils
	for s in idalink.idautils.Segments():
		print "Segment at %x is named %s" % (s, idalink.idc.SegName(s))

	# use idaapi
	for s in idalink.idautils.Functions():
		print "Byte at at %x is %x" % (s, idalink.idaapi.get_byte(s))

And that's that. Basically, you get access to the IDA API from outside of IDA. Good stuff.

## Issues

There are a few issues.

- the whole thing lives in \_\_init\_\_.py. I feel that this is somehow dirty.
- the detection for whether to use idal or idal64 is very simplistic (greps for 32 or 64 in the output of the file command) and probably needs to be improved
