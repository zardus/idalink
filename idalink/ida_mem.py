#!/usr/bin/env python

def ondemand(f):
	name = f.__name__
	def func(self, *args, **kwargs):
		if hasattr(self, "_" + name):
			return getattr(self, "_" + name)

		a = f(self, *args, **kwargs)
		setattr(self, "_" + name, a)
		return a
	func.__name__ = f.__name__
	return func

class IDAMem:
	def __init__(self, ida, initial_mem = None):
		self.ida = ida
		self.local = initial_mem if initial_mem is not None else { }

	def __getitem__(self, b):
		if b in self.local:
			return self.local[b]

		return self.ida.idaapi.get_byte(b)

	def __setitem__(self, b, v):
		self.local[b] = v

	# Gets the "heads" (instructions and data items) and head sizes from IDA
	@ondemand
	def heads(self):
		return { h:self.ida.idc.ItemSize(h) for h in self.ida.idautils.Heads() }

	# Returns a list of bytes that are in memory.
	@ondemand
	def keys(self):
		keys = set()
		for h,s in self.heads().iteritems():
			for i in range(s):
				keys.add(h+i)
		return list(keys)

	# Pulls all the "mapped" memory from IDA
	def pull(self):
		for h,s in self.heads():
			for i in range(s):
				self.local[h+i] = self.ida.idaapi.get_byte(h+i)
