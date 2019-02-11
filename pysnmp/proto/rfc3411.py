#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pysnmp/license.html
#
from pysnmp.proto import rfc1157, rfc1905

READ_CLASS_PDUS = set(
    (rfc1157.GetRequestPDU.tagSet,
     rfc1157.GetNextRequestPDU.tagSet,
     rfc1905.GetRequestPDU.tagSet,
     rfc1905.GetNextRequestPDU.tagSet,
     rfc1905.GetBulkRequestPDU.tagSet)
)

WRITE_CLASS_PDUS = set(
    (rfc1157.SetRequestPDU.tagSet,
     rfc1905.SetRequestPDU.tagSet)
)

RESPONSE_CLASS_PDUS = set(
    (rfc1157.GetResponsePDU.tagSet,
     rfc1905.ResponsePDU.tagSet,
     rfc1905.ReportPDU.tagSet)
)

NOTIFICATION_CLASS_PDUS = set(
    (rfc1157.TrapPDU.tagSet,
     rfc1905.SNMPv2TrapPDU.tagSet,
     rfc1905.InformRequestPDU.tagSet)
)

INTERNAL_CLASS_PDUS = set(
    (rfc1905.ReportPDU.tagSet,)
)

CONFIRMED_CLASS_PDUS = set(
    (rfc1157.GetRequestPDU.tagSet,
     rfc1157.GetNextRequestPDU.tagSet,
     rfc1157.SetRequestPDU.tagSet,
     rfc1905.GetRequestPDU.tagSet,
     rfc1905.GetNextRequestPDU.tagSet,
     rfc1905.GetBulkRequestPDU.tagSet,
     rfc1905.SetRequestPDU.tagSet,
     rfc1905.InformRequestPDU.tagSet)
)

UNCONFIRMED_CLASS_PDUS = set(
    (rfc1157.GetResponsePDU.tagSet,
     rfc1905.ResponsePDU.tagSet,
     rfc1157.TrapPDU.tagSet,
     rfc1905.ReportPDU.tagSet,
     rfc1905.SNMPv2TrapPDU.tagSet)
)
