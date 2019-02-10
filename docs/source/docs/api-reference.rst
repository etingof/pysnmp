
Library reference
=================

.. toctree::
   :maxdepth: 3

Dealing with many SNMP features may quickly overwhelm developers who aim at a 
quick and trivial task, PySNMP employs a layered architecture approach
where the topmost programming API tries to be as simple as possible 
to allow immediate solutions for most common use cases. 

Most of SNMP operations involve packet exchange over network. PySNMP
is shipped with a set of bindings to popular asynchronous Python I/O
frameworks that let you run PySNMP in parallel with other tasks your
application may perform.

High-level, v3arch, sync
------------------------

The synchronous `hlapi.v3arch` API is the easiest to use and probably
the richest in features. However `hlapi.v1arch` API may be faster.

Command Generator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/asyncore/sync/manager/cmdgen/getcmd
   /docs/hlapi/v3arch/asyncore/sync/manager/cmdgen/setcmd
   /docs/hlapi/v3arch/asyncore/sync/manager/cmdgen/nextcmd
   /docs/hlapi/v3arch/asyncore/sync/manager/cmdgen/bulkcmd

Notification Originator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/asyncore/sync/agent/ntforg/notification

Transport configuration
+++++++++++++++++++++++

The following shortcut classes convey configuration information to
SNMP engine's Local Configuration Datastore (:RFC:`2271#section-3.4.2`)
as well as to underlying socket API. Once committed to LCD, SNMP engine
saves its configuration for the lifetime of SNMP engine object.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.UdpTransportTarget
   :members: setLocalAddress

.. autoclass:: pysnmp.hlapi.v3arch.Udp6TransportTarget
   :members: setLocalAddress

High-level v3arch asyncore
--------------------------

The :mod:`asyncore` module is in Python standard library since ancient
times. Main loop is built around :mod:`select` dispatcher, user
code is invoked through callback callables.

Command Generator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/asyncore/manager/cmdgen/getcmd
   /docs/hlapi/v3arch/asyncore/manager/cmdgen/setcmd
   /docs/hlapi/v3arch/asyncore/manager/cmdgen/nextcmd
   /docs/hlapi/v3arch/asyncore/manager/cmdgen/bulkcmd

Notification Originator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/asyncore/agent/ntforg/notification 

Transport configuration
+++++++++++++++++++++++

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.asyncore.UdpTransportTarget
   :members: setLocalAddress

.. autoclass:: pysnmp.hlapi.v3arch.asyncore.Udp6TransportTarget
   :members: setLocalAddress

High-level v3arch asyncio
-------------------------

The :mod:`asyncio` module first appeared in standard library since
Python 3.3 (in provisional basis). Its main design feature is that
it makes asynchronous code looking like synchronous one. That greately
simplifies development and maintanence.

Command Generator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/asyncio/manager/cmdgen/getcmd
   /docs/hlapi/v3arch/asyncio/manager/cmdgen/setcmd
   /docs/hlapi/v3arch/asyncio/manager/cmdgen/nextcmd
   /docs/hlapi/v3arch/asyncio/manager/cmdgen/bulkcmd

Notification Originator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/asyncio/agent/ntforg/notification 

Transport configuration
+++++++++++++++++++++++

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.asyncio.UdpTransportTarget
   :members: setLocalAddress

.. autoclass:: pysnmp.hlapi.v3arch.asyncio.Udp6TransportTarget
   :members: setLocalAddress

High-level v3arch trollius
--------------------------

An almost compatible alternative to *asyncio* for pre-3.3 Python
is `Trollius <http://trollius.readthedocs.org>`_ module. PySNMP's
`asyncio` bindings automatically work with Trolleus.

Please refer to :doc:`Trollius examples </examples/contents>` for
more information.

High-level v3arch twisted
-------------------------

`Twisted <http://twistedmatrix.org>`_ is one of the earliest and hugely
popular asynchronous I/O framework. It introduced a concept of
:class:`~twisted.internet.defer.Deferred` for representing work-in-progress
that is not blocking the rest of I/O operations. PySNMP provides Twisted
bindings.

Command Generator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/twisted/manager/cmdgen/getcmd
   /docs/hlapi/v3arch/twisted/manager/cmdgen/setcmd
   /docs/hlapi/v3arch/twisted/manager/cmdgen/nextcmd
   /docs/hlapi/v3arch/twisted/manager/cmdgen/bulkcmd

Notification Originator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v3arch/twisted/agent/ntforg/notification 

Transport configuration
+++++++++++++++++++++++

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.twisted.UdpTransportTarget
   :members: setLocalAddress

High-level v3arch SNMP Engine
-----------------------------

SNMP Engine is a central, stateful object used by all SNMP v3
subsystems.  Calls to high-level Applications API also consume SNMP
Engine object on input.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.SnmpEngine(snmpEngineID=None)

High-level v3arch auth
----------------------

Calls to high-level Applications API consume Security Parameters
configuration object on input. The shortcut classes described in
this section convey configuration information to SNMP engine's
Local Configuration Datastore (:RFC:`2271#section-3.4.2`).
Once committed to LCD, SNMP engine saves its configuration for
the lifetime of SNMP engine object.

Community-based
+++++++++++++++

Security Parameters object is Security Model specific. The
:py:class:`~pysnmp.hlapi.v3arch.CommunityData`
class is used for configuring Community-Based Security Model of SNMPv1/SNMPv2c.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.CommunityData(communityIndex, communityName=None, mpModel=1, contextEngineId=None, contextName='', tag='')

User-based
++++++++++

The :py:class:`~pysnmp.hlapi.v3arch.UsmUserData` class provides SNMPv3 User-Based
Security Model configuration for SNMP v3 systems.

.. autoclass:: pysnmp.hlapi.v3arch.UsmUserData(userName, authKey=None, privKey=None, authProtocol=USM_AUTH_NONE, privProtocol=USM_PRIV_NONE, securityEngineId=None)

**Authentication protocol identifiers**

.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_NONE
.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_HMAC96_MD5
.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_HMAC96_SHA
.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_HMAC128_SHA224
.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_HMAC192_SHA256
.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_HMAC256_SHA384
.. autodata:: pysnmp.hlapi.v3arch.USM_AUTH_HMAC384_SHA512

**Privacy (encryption) protocol identifiers**

.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_NONE
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CBC56_DES
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CBC168_3DES
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CFB128_AES
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CFB192_AES
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CFB256_AES
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CFB192_AES_BLUMENTHAL
.. autodata:: pysnmp.hlapi.v3arch.USM_PRIV_CFB256_AES_BLUMENTHAL

.. note::

   SNMP authentication and encryption keys must be at least *eight*
   octets long.

Transport configuration is I/O framework specific and is described in
respective sections.

High-level v3arch SNMP Context
------------------------------

SNMP engine may serve several instances of the same MIB within
possibly multiple SNMP entities. SNMP context is a tool for
unambiguously identifying a collection of MIB variables behind the
SNMP engine. See :RFC:`3411#section-3.3.1` for details.

.. note::

   The SNMP context information is not tied to SNMPv3/USM user,
   but it is transferred in SNMPv3 message header.

   Legacy SNMPv1/v2c protocols do not accommodate the SNMP context
   information at all.

   To fit legacy SNMPv1/SNMPv2c systems into unified SNMPv3
   architecture, the mapping procedure is introduced by
   :RFC:`2576#section-5.1` which essentially lets you first configure
   and then supply the missing items (e.g. *contextName*,
   *contextEngineId* and other) to the upper layers of SNMP stack
   based on SNMPv1/v2c *communityName* and transport endpoint.

   The SNMP context information necessary for this mapping procedure
   to operate is supplied through the
   :py:class:`~pysnmp.hlapi.v3arch.CommunityData` object.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v3arch.ContextData

High-level v1arch sync
----------------------

The synchronous `hlapi.v1arch` API is probably the easiest to use and fast to run,
however it does not support SNMPv3.

Command Generator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v1arch/asyncore/sync/manager/cmdgen/getcmd
   /docs/hlapi/v1arch/asyncore/sync/manager/cmdgen/setcmd
   /docs/hlapi/v1arch/asyncore/sync/manager/cmdgen/nextcmd
   /docs/hlapi/v1arch/asyncore/sync/manager/cmdgen/bulkcmd

Notification Originator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v1arch/asyncore/sync/agent/ntforg/notification

Transport configuration
+++++++++++++++++++++++

The following shortcut classes convey configuration information to
SNMP engine's Local Configuration Datastore (:RFC:`2271#section-3.4.2`)
as well as to underlying socket API. Once committed to LCD, SNMP engine
saves its configuration for the lifetime of SNMP engine object.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v1arch.UdpTransportTarget
   :members: setLocalAddress

.. autoclass:: pysnmp.hlapi.v1arch.Udp6TransportTarget
   :members: setLocalAddress

High-level v1arch asyncore
--------------------------

The :mod:`asyncore` module is in Python standard library since ancient
times. Main loop is built around :mod:`select` dispatcher, user
code is invoked through callback callables.

Command Generator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v1arch/asyncore/manager/cmdgen/getcmd
   /docs/hlapi/v1arch/asyncore/manager/cmdgen/setcmd
   /docs/hlapi/v1arch/asyncore/manager/cmdgen/nextcmd
   /docs/hlapi/v1arch/asyncore/manager/cmdgen/bulkcmd

Notification Originator

.. toctree::
   :maxdepth: 2

   /docs/hlapi/v1arch/asyncore/agent/ntforg/notification

Transport configuration
+++++++++++++++++++++++

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v1arch.asyncore.UdpTransportTarget
   :members: setLocalAddress

.. autoclass:: pysnmp.hlapi.v1arch.asyncore.Udp6TransportTarget
   :members: setLocalAddress

High-level v1arch SNMP Dispatcher
---------------------------------

SNMP Dispatcher is a stateful object representing asynchronous
I/O event loop and also holding some caches. Calls to `v1arch`
always require consume SNMP Dispatcher object on input.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v1arch.SnmpDispatcher()

High-level v1arch auth
----------------------

Calls to `v1arch` API require SNMP authentication object on input.

Community-based
+++++++++++++++

Security Parameters object is Security Model specific. The
:py:class:`~pysnmp.hlapi.v1arch.CommunityData`
class is used for configuring Community-Based Security Model of SNMPv1/SNMPv2c.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.hlapi.v1arch.CommunityData(communityName, mpModel=1)

.. _mib-services:

MIB services
------------

.. _mib-variables:

MIB Variables
+++++++++++++

SNMP MIB variable is identified by an OBJECT IDENTIFIER (OID) and is 
accompanied by a value belonging to one of SNMP types (:RFC:`1902#section-2`).
This pair is collectively called a variable-binding in SNMP parlance.

The :py:mod:`~pysnmp.smi.rfc1902` module implements :RFC:`1902#section-2`
MACRO definiitons.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.smi.rfc1902.ObjectIdentity
   :members:

.. autoclass:: pysnmp.smi.rfc1902.ObjectType
   :members:

.. _notification-types:

MIB notification types
++++++++++++++++++++++

SNMP Notifications are enumerated and imply including certain
set of MIB variables.
Notification Originator applications refer to MIBs for MIB notifications
through *NOTIFICATION-TYPE* ASN.1 macro. It conveys a set of MIB variables to 
be gathered and reported in SNMP Notification. The
:py:mod:`~pysnmp.smi.rfc1902` module implements :RFC:`1902#section-2`
macro definiitons.

.. toctree::
   :maxdepth: 2

.. autoclass:: pysnmp.smi.rfc1902.NotificationType
   :members:

.. _snmp-types:

SNMP base types
---------------

SNMP represents real-world objects it serves along with their
states in form of values. Those values each belong to one
of SNMP types (:RFC:`1902#section-2`) which, in turn, are based
on `ASN.1 <https://en.wikipedia.org/wiki/Abstract_Syntax_Notation_One>`_ 
data description language. PySNMP types are derived from
`Python ASN.1 types <http://snmplabs.com/pyasn1/>`_ implementation.

.. toctree::
   :maxdepth: 2

.. _null:

Null type
+++++++++

.. autoclass:: pysnmp.proto.rfc1902.Null(initializer)
   :members:

.. note::

   The `NULL` type actually belongs to the base ASN.1 types. It is not defined
   in :RFC:`1902#section-2` as an SNMP type. The `Null` type is exposed through
   `rfc1902` module just for convenience.

.. _integer32:

Integer32 type
++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Integer32(initializer)
   :members:

.. _integer:

Integer type
++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Integer(initializer)
   :members:

.. _octetstring:

OctetString type
++++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.OctetString(strValue=None, hexValue=None)
   :members:

.. _ipaddress:

IpAddress type
++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.IpAddress(strValue=None, hexValue=None)

ObjectIdentifier type
+++++++++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.ObjectIdentifier(initializer)

Counter32 type
++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Counter32(initializer)

Gauge32 type
++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Gauge32(initializer)

Unsigned32 type
+++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Unsigned32(initializer)

TimeTicks type
++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.TimeTicks(initializer)

Opaque type
+++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Opaque(initializer)

Counter64 type
++++++++++++++

.. autoclass:: pysnmp.proto.rfc1902.Counter64(initializer)

Bits type
+++++++++

.. autoclass:: pysnmp.proto.rfc1902.Bits(initializer)
   :members:
