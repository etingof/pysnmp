
Asynchronous: Twisted
=====================

`Twisted <http://twistedmatrix.com>`_ is quite old and widly used
I/O framework. With Twisted, your code will mostly live in isolated
functions, but unlike as it is with callback-based design, with Twisted
work-in-progress is represented by a
:class:`~twisted.internet.defer.Deferred` class instance effectively
carrying state and context of running operation. Your callback functions
will be attached to these *Deferred* objects and invoked as *Deferred*
is done.

Based on *Twisted* infrastructure, individual asynchronous functions
could be chained to run sequentially or in parallel.

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/twisted/manager/cmdgen/v1-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/twisted/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

To make use of SNMPv3 and USM, the following code performs a series of
SNMP GETNEXT operations effectively fetching a table of SNMP variables
from SNMP Agent:

.. include:: /../../examples/hlapi/twisted/manager/cmdgen/getbulk-to-eom.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/twisted/manager/cmdgen/getbulk-to-eom.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/twisted/manager/cmdgen/snmp-versions
   /examples/hlapi/twisted/manager/cmdgen/walking-operations
   /examples/hlapi/twisted/manager/cmdgen/transport-tweaks
   /examples/hlapi/twisted/manager/cmdgen/advanced-topics

Sending SNMP TRAP's and INFORM's is as easy with PySNMP library.
The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/twisted/agent/ntforg/default-v1-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/twisted/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/twisted/agent/ntforg/common-notifications
   /examples/hlapi/twisted/agent/ntforg/advanced-topics

More sophisticated or less popular SNMP operations can still be performed 
with PySNMP through its Native API to Standard SNMP Applications.
