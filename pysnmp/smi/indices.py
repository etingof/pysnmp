"""Ordered dictionaries classes used for indices"""
from types import DictType, TupleType
from string import join, split, atol
from bisect import bisect

class OrderedDict(DictType):
    def __init__(self, **kwargs):
        self.__keys = []
        self.__dirty = 1
        super(OrderedDict, self).__init__()
        if kwargs:
            self.update(kwargs)
    def __setitem__(self, key, value):
        if key not in self:
            self.__keys.append(key)
        super(OrderedDict, self).__setitem__(key, value)
        self.__dirty = 1
    def __repr__(self):
        if self.__dirty: self.__order()
        return super(OrderedDict, self).__repr__()
    def __str__(self):
        if self.__dirty: self.__order()
        return super(OrderedDict, self).__str__()
    def __delitem__(self, key):
        if super(OrderedDict, self).__contains__(key):
            self.__keys.remove(key)
        super(OrderedDict, self).__delitem__(key)
        self.__dirty = 1            
    __delattr__ = __delitem__
    def clear(self):
        super(OrderedDict, self).clear()
        self.__keys = []
        self.__dirty = 1        
    def keys(self):
        if self.__dirty: self.__order()
        return list(self.__keys)
    def values(self):
        if self.__dirty: self.__order()
        return map(lambda k, d=self: d[k], self.__keys)
    def items(self):
        if self.__dirty: self.__order()
        return map(lambda k, d=self: (k, d[k]), self.__keys)
    def update(self, d):
        map(lambda (k, v), self=self: self.__setitem__(k, v), d.items())
    def sortingFun(self, keys): keys.sort()
    def __order(self):
        self.sortingFun(self.__keys)
        d = {}
        for k in self.__keys:
            d[len(k)] = 1
        l = d.keys()
        l.sort(); l.reverse()
        self.__keysLens = tuple(l)
        self.__dirty = 0
    def nextKey(self, key):
        keys = self.keys()
        if key in self:
            nextIdx = keys.index(key) + 1            
        else:
            nextIdx = bisect(keys, key)
        if nextIdx < len(keys):
            return keys[nextIdx]
        else:
            raise KeyError(key)

    def getKeysLens(self):
        if self.__dirty:
            self.__order()
        return self.__keysLens

class OidOrderedDict(OrderedDict):
    def __init__(self, **kwargs):
        self.__keysCache = {}
        apply(OrderedDict.__init__, [self], kwargs)

    def __setitem__(self, key, value):
        if key not in self.__keysCache:
            if type(key) == TupleType:
                self.__keysCache[key] = key
            else:
                self.__keysCache[key] = map(
                    lambda x: atol(x), filter(None, split(key, '.'))
                    )
        OrderedDict.__setitem__(self, key, value)

    def __delitem__(self, key):
        if key in self.__keysCache:
            del self.__keysCache[key]
        OrderedDict.__delitem__(self, key)
    __delattr__ = __delitem__

    def sortingFun(self, keys):
        def f(o1, o2, self=self):
            return cmp(self.__keysCache[o1], self.__keysCache[o2])
        keys.sort(f)
