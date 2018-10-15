# -*- coding: utf-8 -*-

# Copyright (C) 2013- Yan Shoshitaishvili aka. zardus
#                     Ruoyu Wang aka. fish
#                     Audrey Dutcher aka. rhelmot
#                     Kevin Borgolte aka. cao

__all__ = ['get_memory', 'IDAMemory', 'CachedIDAMemory',
           'IDAPermissions', 'CachedIDAPermissions']

import collections
import itertools
import logging
import operator
LOG = logging.getLogger('idalink.ida_mem')


# Helper functions.
def _dict_values_sorted_by_key(dictionary):
    # This should be a yield from instead.
    """Internal helper to return the values of a dictionary, sorted by key.
    """
    for _, value in sorted(dictionary.iteritems(), key=operator.itemgetter(0)):
        yield value


def _ondemand(f):
    """Decorator to only request information if not in cache already.
    """
    name = f.__name__

    def func(self, *args, **kwargs):
        if not args and not kwargs:
            if hasattr(self, '_%s' % name):
                return getattr(self, '_%s' % name)

            a = f(self, *args, **kwargs)
            setattr(self, '_%s' % name, a)
            return a
        else:
            return f(self, *args, **kwargs)
    func.__name__ = name
    return func


# Functions others are allowed to call.
def get_memory(idaapi, start, size, default_byte=None):
    # TODO: Documentation
    if idaapi is None:
        idaapi = __import__('idaapi')

    if size == 0:
        return {}

    # We are optimistic and assume it's a continous memory area
    at_address = idaapi.get_many_bytes(start, size)

    d = {}
    if at_address is None:    # It was not, resort to binary research
        if size == 1:
            if default_byte is not None:
                LOG.debug('Using default byte for %d', start)
                d[start] = default_byte
            return d

        mid = start + size / 2
        first_size = mid - start
        second_size = size - first_size

        left = get_memory(idaapi, start, first_size, default_byte=default_byte)
        right = get_memory(idaapi, mid, second_size, default_byte=default_byte)

        if default_byte is None:
            # will be nonsequential
            d.update(left)
            d.update(right)
        else:
            # it will be sequential, so let's combine it
            chained = itertools.chain(_dict_values_sorted_by_key(left),
                                      _dict_values_sorted_by_key(right))
            d[start] = ''.join(chained)
    else:
        d[start] = at_address

    return d


class IDAKeys(collections.MutableMapping):  # pylint: disable=W0223
    # TODO: delitem, setitem, getitem are abstract, should be fixed,
    #       disabled warning should be removed
    def __init__(self, ida):
        self.ida = ida

    # Gets the "heads" (instructions and data items) and head sizes from IDA
    @_ondemand
    def heads(self, exclude=()):
        # TODO: Documentation
        LOG.debug('Getting heads from IDA for file %s', self.ida.filename)
        keys = [-1] + list(exclude) + [self.ida.idc.MAXADDR + 1]
        ranges = []
        for i in range(len(keys) - 1):
            a, b = keys[i], keys[i+1]
            if a - b > 1:
                ranges.append((a+1, b-1))

        heads = {}
        for start, end in ranges:
            for head in self.ida.idautils.Heads(start, end, 1):
                heads[head] = self.ida.idc.ItemSize(head)
        return heads

    @_ondemand
    def segments(self):
        # TODO: Documentation
        LOG.debug('Getting segments from IDA for file %s', self.ida.filename)
        segments_size = {}
        for s in self.ida.idautils.Segments():
            segments_size[s] = self.ida.idc.SegEnd(s) - self.ida.idc.SegStart(s)
        return segments_size

    @_ondemand
    def idakeys(self):
        # TODO: Documentation
        keys = set()
        for h, s in self.segments().iteritems():
            for i in range(s):
                keys.add(h + i)
        for h, s in self.heads(exclude=keys).iteritems():
            for i in range(s):
                keys.add(h + i)
        LOG.debug('Done getting keys.')
        return keys

    def __iter__(self):
        # TODO: Refactor to be more pythonic
        for key in self.idakeys():
            yield key

    def __len__(self):
        # This is significantly faster than list(self.__iter__) because
        # we do not need to keep the whole list in memory, just the accumulator.
        return sum(1 for _ in self)

    def __contains__(self, key):
        return key in self.keys()

    def reset(self):
        # TODO: Documentation
        if hasattr(self, '_heads'):
            delattr(self, '_heads')
        if hasattr(self, '_segments'):
            delattr(self, '_segments')
        if hasattr(self, '_idakeys'):
            delattr(self, '_idakeys')


class IDAPermissions(IDAKeys):
    def __init__(self, ida, default_perm=7):
        super(IDAPermissions, self).__init__(ida)
        self.default_perm = default_perm

    def __getitem__(self, address):
        # Only do things that we actually have in IDA
        if address not in self:
            raise KeyError(address)

        seg_start = self.ida.idc.SegStart(address)
        if seg_start == self.ida.idc.BADADDR:
            # We can really only return the default here
            return self.default_perm

        return self.ida.idc.GetSegmentAttr(seg_start, self.ida.idc.SEGATTR_PERM)

    def __setitem__(self, address, value):
        # Nothing we can do here
        pass

    def __delitem__(self, address, value):
        # Nothing we can do here
        pass


class CachedIDAPermissions(IDAPermissions):
    def __init__(self, ida, default_perm=7):
        super(CachedIDAPermissions, self).__init__(ida)
        self.permissions = {}
        self.default_perm = default_perm

    def __getitem__(self, address):
        if address in self.permissions:
            return self.permissions[address]
        p = super(CachedIDAPermissions, self).__getitem__(address)

        # cache the segment
        seg_start = self.ida.idc.SegStart(address)
        seg_end = self.ida.idc.SegEnd(address)
        if seg_start == self.ida.idc.BADADDR:
            self.permissions[address] = p
        else:
            for i in range(seg_start, seg_end):
                self.permissions[i] = p

        return p

    def __setitem__(self, address, value):
        self.permissions[address] = value

    def __delitem__(self, address):
        self.permissions.pop(address, None)

    def reset(self):
        # TODO: Documentation
        self.permissions.clear()
        super(CachedIDAPermissions, self).reset()


class IDAMemory(IDAKeys):
    def __init__(self, ida, default_byte=chr(0xff)):
        super(IDAMemory, self).__init__(ida)
        self.default_byte = default_byte

    def __getitem__(self, address):
        # only do things that we actually have in IDA
        if address not in self:
            raise KeyError(address)

        value = self.ida.idaapi.get_many_bytes(address, 1)
        if value is None:
            value = self.default_byte
        return value

    def __setitem__(self, address, value):
        self.ida.idaapi.patch_byte(address, value)

    def __delitem__(self, address):
        # nothing we can really do here
        pass


class CachedIDAMemory(IDAMemory):
    def __init__(self, ida, default_byte=chr(0xff)):
        super(CachedIDAMemory, self).__init__(ida, default_byte)
        self.local = {}
        self._pulled = False

    @property
    def pulled(self):
        """Check if memory has been pulled from the remote link.
        """
        return self._pulled

    def __getitem__(self, address):
        if address in self.local:
            return self.local[address]

        LOG.debug('Uncached byte: 0x%x', address)
        one = super(CachedIDAMemory, self).__getitem__(address)

        # cache the byte if it's not in a segment
        seg_start = self.ida.idc.SegStart(address)
        if seg_start == self.ida.idc.BADADDR:
            self.local[address] = one
        else:
            # otherwise, cache the segment
            seg_end = self.ida.idc.SegEnd(address)
            seg_size = seg_end - seg_start
            self._load_memory(seg_start, seg_size)

        return one

    def __iter__(self):
        if self.pulled:
            return self.local.__iter__()
        else:
            return super(CachedIDAMemory, self).__iter__()

    def __setitem__(self, address, value):
        self.local[address] = value

    def __delitem__(self, address):
        self.local.pop(address, None)

    def get_memory(self, start, size):
        """Retrieve an area of memory from IDA.
        Returns a sparse dictionary of address -> value.
        """
        LOG.debug('get_memory: %d bytes from %x', size, start)
        return get_memory(self.ida.idaapi, start, size,
                          default_byte=self.default_byte)

    def pull_defined(self):
        if self.pulled:
            return

        start = self.ida.idc.MinEA()
        size = self.ida.idc.MaxEA() - start

        LOG.debug('Loading memory of %s (%d bytes)...', self.ida.filename, size)
        chunks = self.ida.remote_idalink_module.get_memory(None, start, size)

        LOG.debug('Storing loaded memory of %s...', self.ida.filename)
        self._store_loaded_chunks(chunks)

        self._pulled = True

    def reset(self):
        self.local.clear()
        self._pulled = False
        super(CachedIDAMemory, self).reset()

    # Helpers
    def _load_memory(self, start, size):
        chunks = self.get_memory(start, size)
        self.store_loaded_chunks(chunks)

    def _store_loaded_chunks(self, chunks):
        LOG.debug('Updating cache with %d chunks', len(chunks))
        for start, buff in chunks.iteritems():
            for n, i in enumerate(buff):
                if start + n not in self.local:
                    self.local[start + n] = i
