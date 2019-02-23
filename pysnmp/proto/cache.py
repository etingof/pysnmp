#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.proto import error


class Cache(object):
    def __init__(self):
        self._cacheRepository = {}

    def add(self, index, **kwargs):
        self._cacheRepository[index] = kwargs
        return index

    def pop(self, index):
        if index in self._cacheRepository:
            cachedParams = self._cacheRepository[index]
        else:
            return
        del self._cacheRepository[index]
        return cachedParams

    def update(self, index, **kwargs):
        if index not in self._cacheRepository:
            raise error.ProtocolError(
                'Cache miss on update for %s' % kwargs
            )
        self._cacheRepository[index].update(kwargs)

    def expire(self, cbFun, cbCtx):
        for index, cachedParams in list(self._cacheRepository.items()):
            if cbFun:
                if cbFun(index, cachedParams, cbCtx):
                    if index in self._cacheRepository:
                        del self._cacheRepository[index]
