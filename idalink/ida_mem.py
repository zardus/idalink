#!/usr/bin/env python

import collections
import logging
l = logging.getLogger("idalink.ida_mem")

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

class IDAKeys(collections.MutableMapping):
	def __init__(self, ida):
		self.ida = ida

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

	# Iterates over the addresses that are loaded in IDA
	@ondemand
	def idakeys(self):
		keys = set()
		l.debug("Getting segment addresses.")
		for h,s in self.segments().iteritems():
			for i in range(s):
				keys.add(h+i)
		l.debug("Getting non-segment addresses.")
		for h,s in self.heads(exclude=keys).iteritems():
			for i in range(s):
				keys.add(h+i)
		l.debug("Done getting keys.")
		return keys

	def __iter__(self):
		for k in self.idakeys():
			yield k

	def __len__(self):
		return len(list(self.__iter__()))

	def __contains__(self, k):
		return k in self.keys()

class IDAPerms(IDAKeys):
	def __init__(self, ida, default_perm=7):
		super(IDAPerms, self).__init__(ida)

	def __getitem__(self, b):
		# only do things that we actually have in IDA
		if b not in self:
			raise KeyError(b)
		seg_start = self.ida.idc.SegStart(b)
		if seg_start == self.ida.idc.BADADDR:
			# we can really only return the default here
			return self.default_perm
		return self.ida.idc.GetSegmentAttr(seg_start, self.ida.idc.SEGATTR_PERM)

	def __setitem__(self, b, v):
		# nothing we can really do here
		pass

	def __delitem__(self, b):
		# nothing we can really do here
		pass

class CachedIDAPerms(IDAPerms):
	def __init__(self, ida, default_perm=7):
		super(CachedIDAPerms, self).__init__(ida)
		self.permissions = { }
		self.default_perm = default_perm

	def __getitem__(self, b):
		if b in self.permissions: return self.permissions[b]
		p = super(CachedIDAPerms, self).__getitem__(b)

		# cache the segment
		seg_start = self.ida.idc.SegStart(b)
		seg_end = self.ida.idc.SegEnd(b)
		if seg_start == self.ida.idc.BADADDR:
			self.permissions[b] = p
		else:
			for i in range(seg_start, seg_end):
				self.permissions[i] = p

		return p

	def __setitem__(self, b, v):
		self.permissions[b] = v

	def __delitem__(self, b):
		self.permissions.pop(b, None)

class IDAMem(IDAKeys):
	def __init__(self, ida, default_byte=chr(0xff)):
		super(IDAMem, self).__init__(ida)

	def __getitem__(self, b):
		# only do things that we actually have in IDA
		if b not in self:
			raise KeyError(b)
		v = self.ida.idaapi.get_many_bytes(b, 1)
		return v if v is not None else self.default_byte

	def __setitem__(self, b, v):
		self.ida.idaapy.patch_byte(b, v)

	def __delitem__(self, b):
		# nothing we can really do here
		pass

class CachedIDAMem(IDAMem):
	def __init__(self, ida, default_byte=chr(0xff)):
		super(CachedIDAMem, self).__init__(ida)
		self.local = { }
		self.default_byte = default_byte

	def __getitem__(self, b):
		if b in self.local: return self.local[b]

		one = super(CachedIDAMem, self).__getitem__(b)

		# cache the byte if it's not in a segment
		seg_start = self.ida.idc.SegStart(b)
		if seg_start == self.ida.idc.BADADDR:
			self.local[b] = one
		else:
			# otherwise, cache the segment
			seg_end = self.ida.idc.SegEnd(b)
			seg_size = seg_end - seg_start
			l.debug("Loading %d bytes from 0x%x" % (seg_size, seg_start))
			self.load_memory(seg_start, seg_size)

		return one

	def __setitem__(self, b, v):
		self.local[b] = v

	def __delitem__(self, k):
		self.local.pop(k, None)

	# tries to quickly get a bunch of memory from IDA
	# returns a dictionary where d[start] = content to support sparsely-defined memory in IDA
	def get_memory(self, start, size):
		d = { }
		if size == 0:
			return d

		b = self.ida.idaapi.get_many_bytes(start, size)
		if b is None:
			if size == 1:
				d[start] = self.default_byte
				return d

			mid = start + size/2
			first_size = mid - start
			second_size = size - first_size

			#l.debug("Split range [%x,%x) into [%x,%x) and [%x,%x)" %
			#   (start, start + size, start, start + first_size, mid, mid + second_size))

			d.update(self.get_memory(start, first_size))
			d.update(self.get_memory(mid, second_size))
		else:
			d[start] = b

		return d

	def load_memory(self, start, size):
		contents = self.get_memory(start, size)

		for start, bytes in contents.iteritems():
			for n,i in enumerate(bytes):
				if start+n not in self.local:
					self.local[start+n] = i

	def reset(self):
		self.local.clear()

		if hasattr(self, "_heads"): delattr(self, "_heads")
		if hasattr(self, "_segments"): delattr(self, "_segments")
