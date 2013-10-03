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
	def __init__(self, ida, initial_mem = None, caching = True, lazy = True):
		self.ida = ida
		self.local = initial_mem if initial_mem is not None else { }
		self.caching = caching

		if not lazy:
			self.pull()

	def __getitem__(self, b):
		if b in self.local:
			return self.local[b]

		r = self.ida.idaapi.get_byte(b)
		if self.caching:
			self.local[b] = r
		return r

	def __setitem__(self, b, v):
		self.local[b] = v

	def __contains__(self, b):
		return b in self.keys()

	def has_key(self, k):
		return k in self.keys()

	# stuff that needs to be intercepted
	def values(self):
		self.pull()
		return self.local.values()

	def items(self):
		self.pull()
		return self.local.items()

	def iteritems(self):
		self.pull()
		return self.local.iteritems()

	def itervalues(self):
		self.pull()
		return self.local.itervalues()

	def viewitems(self):
		self.pull()
		return self.local.viewitems()

	def viewkeys(self):
		self.pull()
		return self.local.viewkeys()

	def viewvalues(self):
		self.pull()
		return self.local.viewvalues()


	# Gets the "heads" (instructions and data items) and head sizes from IDA
	@ondemand
	def heads(self):
		return { h:self.ida.idc.ItemSize(h) for h in self.ida.idautils.Heads() }

	@ondemand
	def segments(self):
		return { s:(self.ida.idc.SegEnd(s) - self.ida.idc.SegStart(s)) for s in self.ida.idautils.Segments() }

	# Returns a list of bytes that are in memory.
	@ondemand
	def ida_keys(self):
		keys = set()
		for h,s in self.heads().iteritems():
			for i in range(s):
				keys.add(h+i)
		for h,s in self.segments().iteritems():
			for i in range(s):
				keys.add(h+i)
		return list(keys)

	def keys(self):
		return list(set(self.ida_keys() + self.local.keys()))

	# Pulls all the "mapped" memory from IDA
	def pull(self):
		for k in self.keys():
			self.local[k] = self.ida.idaapi.get_byte(k)
