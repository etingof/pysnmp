#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
import random

random.seed()


class Integer(object):
    """Return a next value in a reasonably MT-safe manner"""

    def __init__(self, maximum, increment=256):
        self._maximum = maximum
        if increment >= maximum:
            increment = maximum

        self._increment = increment
        self._threshold = increment // 2

        e = random.randrange(self._maximum - self._increment)

        self._bank = list(range(e, e + self._increment))

    def __repr__(self):
        return '%s(%d, %d)' % (
            self.__class__.__name__, self._maximum, self._increment)

    def __call__(self):
        v = self._bank.pop(0)

        if v % self._threshold:
            return v

        # Should be MT-safe unless too many (~ increment/2) threads
        # bump into this code simultaneously
        e = self._bank[-1] + 1
        if e > self._maximum:
            e = 0

        self._bank.extend(range(e, e + self._threshold))

        return v
