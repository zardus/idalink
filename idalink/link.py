#!/usr/bin/env python

# This code is GPLv3. See LICENSE file.

import os
import rpyc
import time
import random
import subprocess
import socket

from ida_mem import IDAMem, IDAPerms, CachedIDAMem, CachedIDAPerms

IDAMem, IDAPerms # to stop complaining

# various locations
module_dir = os.path.dirname(os.path.realpath(__file__))
log_file = "/tmp/idalink.log"
ida_dir = module_dir

import logging
l = logging.getLogger("idalink")

def spawn_ida(filename, ida_prog, port):
	fullpath = os.path.realpath(os.path.expanduser(filename))

	# $IDADIR/$IDABIN -A -S"$SCRIPT $ARGS" -L$LOGFILE $FILE

	ida_bin = ida_dir + "/" + ida_prog
	server_script = module_dir + "/server.py"
	server_args = str(port)

	l.info("Launching IDA (%s) on %s, listening on port %d, logging to %s" % (ida_bin, fullpath, port, log_file))

	command = [ "screen", "-d", "-m", "-L", "--" ] # run IDA through screen because otherwise its UI hangs
	command += [ module_dir + "/ida_env.sh" ] # IDA needs some environment variables set (specifically, the TERM)
	command += [ ida_bin, "-A" ] # run IDA in automatic mode
	command += [ "-S" + server_script + " " + server_args ] # run our server script in IDA
	command += [ "-L" + log_file ] # log stuff
	command += [ fullpath ] # and, of course, load our file
	subprocess.call(command)

def connect_ida(port):
	link = rpyc.classic.connect("localhost", port)
	l.debug("Connected!")

	idc = link.root.getmodule("idc")
	idaapi = link.root.getmodule("idaapi")
	idautils = link.root.getmodule("idautils")

	return link, idc, idaapi, idautils

class IDALinkError(Exception):
	pass

class IDALink:
	def __init__(self, filename, ida_prog, connect_retries = 60, port = None, initial_mem = { }):
		port = port if port else random.randint(40000, 49999)
		spawn_ida(filename, ida_prog, port)
                self.filename = filename

		for t in range(connect_retries):
			# TODO: detect IDA failure intelligently
			try:
				time.sleep(1)
				l.debug("Trying to connect to IDA on port %d" % port)
				self.link, self.idc, self.idaapi, self.idautils = connect_ida(port)
				self.mem = CachedIDAMem(self, initial_mem)
				self.perms = CachedIDAPerms(self, initial_mem)
				return
			except socket.error:
				l.debug("... failed. Retrying.")

		raise IDALinkError("Failed to connect to IDA on port %d for filename %s" % (port, filename))

        def get_filename(self):
                return self.filename
