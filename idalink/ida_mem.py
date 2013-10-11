#!/usr/bin/env python

import itertools
import logging
l = logging.getLogger("ida_mem")

def ondemand(f):
	name = f.__name__
	def func(self, *args, **kwargs):
		if len(args) + len(kwargs) == 0:
			if hasattr(self, "_" + name):
				return getattr(self, "_" + name)

			a = f(self, *args, **kwargs)
			setattr(self, "_" + name, a)
			return a
		else:
			return f(self, *args, **kwargs)
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
	def heads(self, exclude = ()):
		keys = [ -1 ] + list(exclude) + [ self.ida.idc.MAXADDR + 1 ]
		ranges = [ j for j in [ ((keys[i]+1, keys[i+1]-1) if keys[i+1] - keys[i] > 1 else ()) for i in range(len(keys)-1) ] if j ]

		heads = { }
		for a,b in ranges:
			r_heads = { h:self.ida.idc.ItemSize(h) for h in self.ida.idautils.Heads(a,b+1) }
			heads.update(r_heads)
		return heads

	@ondemand
	def segments(self):
		return { s:(self.ida.idc.SegEnd(s) - self.ida.idc.SegStart(s)) for s in self.ida.idautils.Segments() }

	# Returns a list of bytes that are in memory.
	@ondemand
	def ida_keys(self):
		keys = set()
		for h,s in self.segments().iteritems():
			for i in range(s):
				keys.add(h+i)
		for h,s in self.heads(exclude=keys).iteritems():
			for i in range(s):
				keys.add(h+i)
		return list(keys)

	def keys(self):
		return list(set(self.ida_keys() + self.local.keys()))

	# tries to quickly load a bunch of memory from IDA
	# returns a dictionary where d[start] = content to support sparsely-defined memory in IDA
	def load_memory(self, start, size):
		d = { }
		if size == 0:
			return d

		b = self.ida.idaapi.get_many_bytes(start, size)
		if b is None:
			if size == 1:
				return d

			mid = start + size/2
			first_size = mid - start
			second_size = size - first_size

			#l.debug("Split range [%x,%x) into [%x,%x) and [%x,%x)", start, start + size, start, start + first_size, mid, mid + second_size)

			d.update(self.load_memory(start, first_size))
			d.update(self.load_memory(mid, second_size))
		else:
			d[start] = b

		return d

	# Pulls all the "mapped" memory from IDA
	def pull(self):
		keys = self.ida_keys()
		def kf(x, c=itertools.count()):
			return next(c)-x

		ranges = [ (r[0], r[-1]) for r in [ list(g) for (x,g) in itertools.groupby(keys, kf) ] ]

		for a,b in ranges:
			size = b-a+1
			contents = self.load_memory(a, size)

			for start, bytes in contents.iteritems():
				for n,i in enumerate(bytes):
					self.local[start+n] = i
