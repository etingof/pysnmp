
Asynchronous: asyncore
======================

With :mod:`asyncore` API your scripts get CPU time on :mod:`socket`
events being watched for by :mod:`select` dispatcher. Your code
live mostly in isolated functions (or any callable objects).

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/asyncore/manager/cmdgen/v2c-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/manager/cmdgen/v2c-get.py
   :start-after: """#
   :language: python

To make use of SNMPv3 and USM, the following code performs a series of
SNMP GETNEXT operations effectively fetching a table of SNMP variables
from SNMP Agent:

.. include:: /../../examples/hlapi/asyncore/manager/cmdgen/pull-whole-mib.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/manager/cmdgen/pull-whole-mib.py
   :start-after: """#
   :language: python

More examples on Command Generator API usage follow.

.. toctree::

   /examples/hlapi/asyncore/manager/cmdgen/snmp-versions
   /examples/hlapi/asyncore/manager/cmdgen/walking-operations
   /examples/hlapi/asyncore/manager/cmdgen/advanced-topics

Sending SNMP TRAP's and INFORM's is as easy with PySNMP library.
The following code sends SNMP TRAP:

.. include:: /../../examples/hlapi/asyncore/agent/ntforg/default-v1-trap.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/asyncore/agent/ntforg/default-v1-trap.py
   :start-after: """#
   :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/asyncore/agent/ntforg/common-notifications
   /examples/hlapi/asyncore/agent/ntforg/advanced-topics

More sophisticated or less popular SNMP operations can still be performed 
with PySNMP through its Native API to Standard SNMP Applications.
