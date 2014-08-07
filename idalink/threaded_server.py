#!/usr/bin/env python

# This code is GPLv3. See LICENSE file.

import threading

class ThreadedServer(threading.Thread):
	def __init__(self, port):
		threading.Thread.__init__(self)
		self.port = port

	def run(self):
		import idc
		from rpyc.core import SlaveService
		from rpyc.utils.server import ThreadedServer
		#from rpyc.utils.server import OneShotServer

		#idc.Wait()
		ThreadedServer(SlaveService, port=self.port).start()
		#idc.Exit(0)

def threaded_server(port):
	return ThreadedServer(port).start()
