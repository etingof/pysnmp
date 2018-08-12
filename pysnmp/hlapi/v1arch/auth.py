#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#

__all__ = ['CommunityData']


class CommunityData(object):
    """Creates SNMP v1/v2c configuration entry.

    This object can be used by
    :py:class:`~pysnmp.hlapi.v1arch.asyncore.AsyncCommandGenerator` or
    :py:class:`~pysnmp.hlapi.v1arch.asyncore.AsyncNotificationOriginator`
    and their derivatives for conveying SNMP v1/v2c configuration.

    Parameters
    ----------
    communityName: py:class:`str`
        SNMP v1/v2c community string.
    mpModel: py:class:`int`
        SNMP version - 0 for SNMPv1 and 1 for SNMPv2c.

    Examples
    --------
    >>> from pysnmp.hlapi.v1arch import CommunityData
    >>> CommunityData('public')
    CommunityData(communityName=<COMMUNITY>, mpModel=1)
    """

    def __init__(self, communityName, mpModel=1):
        self.mpModel = mpModel
        self.communityName = communityName

    def __hash__(self):
        return hash((self.communityName, self.mpModel))

    def __repr__(self):
        return '%s(communityName=<COMMUNITY>, mpModel=%r)' % (
            self.__class__.__name__,
            self.communityName,
            self.mpModel,
        )
