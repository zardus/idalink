#!/usr/bin/env python

# This code is GPLv3. See LICENSE file.

import os
import rpyc
import time
import random
import subprocess
import collections

from ida_mem import IDAMem

# various locations
module_dir = os.path.dirname(os.path.realpath(__file__))
log_file = "/tmp/idalink.log"
ida_script = module_dir + "/run_ida.sh"
ida_dir = module_dir

import logging
l = logging.getLogger("idalink")
l.info("IDA launch script: %s" % ida_script)

def spawn_ida(filename, port):
	fullpath = os.path.realpath(os.path.expanduser(filename))
	l.info("Launching IDA on %s" % fullpath)
	subprocess.call([ "screen", "-d", "-m", "--", ida_script, ida_dir, fullpath, log_file, module_dir + "/server.py", str(port) ])

def connect_ida(port):
	link = rpyc.classic.connect("localhost", port)

	idc = link.root.getmodule("idc")
	idaapi = link.root.getmodule("idaapi")
	idautils = link.root.getmodule("idautils")

	return link, idc, idaapi, idautils

class IDALinkError(Exception):
	pass

class IDALink:
	def __init__(self, filename, connect_retries = 60, port = None, initial_mem = None):
		port = port if port else random.randint(40000, 49999)
		spawn_ida(filename, port)

		for t in range(connect_retries):
			# TODO: detect IDA failure intelligently
			try:
				time.sleep(1)
				l.debug("Trying to connect to IDA on port %d" % port)
				self.link, self.idc, self.idaapi, self.idautils = connect_ida(port)
				self.mem = IDAMem(self, initial_mem)
				return
			except Exception:
				l.debug("... failed. Retrying.")

		raise IDALinkError("Failed to connect to IDA on port %d for filename %s" % (port, filename))
