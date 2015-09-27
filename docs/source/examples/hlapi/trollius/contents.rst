
Asynchronous: trollius
======================

In order to use :mod:`asyncio` features with older Python (2.6+), you
could download and install `Trollius <http://trollius.readthedocs.org/>`_
module. PySNMP's *asyncio* bindings will work with Trollius as well.

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/trollius/manager/cmdgen/v1-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/trollius/manager/cmdgen/v1-get.py
   :start-after: """#
   :language: python

To make use of SNMPv3 and USM, the following code performs a series of
SNMP GETNEXT operations effectively fetching a table of SNMP variables
from SNMP Agent:

.. include:: /../../examples/hlapi/trollius/manager/cmdgen/getbulk-to-eom.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/trollius/manager/cmdgen/getbulk-to-eom.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/trollius/manager/cmdgen/snmp-versions
   /examples/hlapi/trollius/manager/cmdgen/walking-operations

Sending SNMP TRAP's and INFORM's is as easy with PySNMP library.
The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/trollius/agent/ntforg/default-v1-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/trollius/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/trollius/agent/ntforg/common-notifications

More sophisticated or less popular SNMP operations can still be performed 
with PySNMP through its Native API to Standard SNMP Applications.
