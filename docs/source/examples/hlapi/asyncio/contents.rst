
Asynchronous: asyncio
=====================

The :mod:`asyncio` module first appeared in standard library since
Python 3.3 (in provisional basis). Its main design feature is that it
makes asynchronous code looking like synchronous one thus eliminating
"callback hell".

With `asyncio` built-in facilities, you could run many SNMP queries
in parallel and/or sequentially, interleave SNMP queries with I/O
operations with other systems. See `asyncio resources <http://asyncio.org>`_
repository for other `asyncio`-compatible modules.

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/asyncio/manager/cmdgen/v1-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncio/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

To make use of SNMPv3 and USM, the following code performs a series of
SNMP GETNEXT operations effectively fetching a table of SNMP variables
from SNMP Agent:

.. include:: /../../examples/hlapi/asyncio/manager/cmdgen/getbulk-to-eom.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncio/manager/cmdgen/getbulk-to-eom.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/asyncio/manager/cmdgen/snmp-versions
   /examples/hlapi/asyncio/manager/cmdgen/walking-operations
   /examples/hlapi/asyncio/manager/cmdgen/advanced-topics

Sending SNMP TRAP's and INFORM's is as easy with PySNMP library.
The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/asyncio/agent/ntforg/default-v1-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncio/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/asyncio/agent/ntforg/common-notifications
   /examples/hlapi/asyncio/agent/ntforg/advanced-topics

More sophisticated or less popular SNMP operations can still be performed 
with PySNMP through its Native API to Standard SNMP Applications.
