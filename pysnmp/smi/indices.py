#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from bisect import bisect


class OrderedDict(dict):
    """Ordered dictionary used for indices"""

    def __init__(self, *args, **kwargs):
        super(OrderedDict, self).__init__()

        self._keys = []
        self._dirty = True
        self._keysLens = []

        if args:
            self.update(*args)

        if kwargs:
            self.update(**kwargs)

    def __setitem__(self, key, value):
        super(OrderedDict, self).__setitem__(key, value)
        if key not in self._keys:
            self._keys.append(key)
            self._dirty = True

    def __delitem__(self, key):
        super(OrderedDict, self).__delitem__(key)
        if key in self._keys:
            self._keys.remove(key)
            self._dirty = True

    def clear(self):
        super(OrderedDict, self).clear()
        self._keys = []
        self._dirty = True

    def keys(self):
        if self._dirty:
            self._order()
        return list(self._keys)

    def values(self):
        if self._dirty:
            self._order()
        return [self[k] for k in self._keys]

    def items(self):
        if self._dirty:
            self._order()

        return [(k, self[k]) for k in self._keys]

    def update(self, *args, **kwargs):
        if args:
            iterable = args[0]
            if hasattr(iterable, 'keys'):
                for k in iterable:
                    self[k] = iterable[k]

            else:
                for k, v in iterable:
                    self[k] = v

        if kwargs:
            for k in kwargs:
                self[k] = kwargs[k]

    def sortingFun(self, keys):
        keys.sort()

    def _order(self):
        self.sortingFun(self._keys)

        self._keysLens = sorted(
            set(len(k) for k in self._keys), reverse=True)

        self._dirty = False

    def nextKey(self, key):
        if self._dirty:
            self._order()

        keys = self._keys

        if key in keys:
            nextIdx = keys.index(key) + 1

        else:
            nextIdx = bisect(keys, key)

        if nextIdx < len(keys):
            return keys[nextIdx]

        else:
            raise KeyError(key)

    def getKeysLens(self):
        if self._dirty:
            self._order()

        return self._keysLens


class OidOrderedDict(OrderedDict):
    """OID-ordered dictionary used for indices"""

    def __init__(self, *args, **kwargs):
        OrderedDict.__init__(self, *args, **kwargs)

        self._keysCache = {}

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)

        if key not in self._keysCache:
            if isinstance(key, tuple):
                self._keysCache[key] = key

            else:
                self._keysCache[key] = [int(x) for x in key.split('.') if x]

    def __delitem__(self, key):
        OrderedDict.__delitem__(self, key)

        if key in self._keysCache:
            del self._keysCache[key]

    def sortingFun(self, keys):
        keys.sort(key=lambda k, d=self._keysCache: d[k])
