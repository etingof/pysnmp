#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
# Limited-size dictionary-like class to use for caches
#


class Cache(object):
    def __init__(self, maxSize=256):
        self._maxSize = maxSize
        self._size = 0
        self._chopSize = maxSize // 10
        self._chopSize = self._chopSize or 1
        self._cache = {}
        self._usage = {}

    def __contains__(self, k):
        return k in self._cache

    def __getitem__(self, k):
        self._usage[k] += 1
        return self._cache[k]

    def __len__(self):
        return self._size

    def __setitem__(self, k, v):
        if self._size >= self._maxSize:
            usageKeys = sorted(
                self._usage, key=lambda x, d=self._usage: d[x])

            for _k in usageKeys[:self._chopSize]:
                del self._cache[_k]
                del self._usage[_k]

            self._size -= self._chopSize

        if k not in self._cache:
            self._size += 1
            self._usage[k] = 0

        self._cache[k] = v

    def __delitem__(self, k):
        del self._cache[k]
        del self._usage[k]
        self._size -= 1
