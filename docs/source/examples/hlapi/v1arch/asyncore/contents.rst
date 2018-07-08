
Asynchronous: asyncore
======================

With :mod:`asyncore` API your scripts get CPU time on :mod:`socket`
events being watched for by :mod:`select` dispatcher. Your code
live mostly in isolated functions (or any callable objects).

In most examples approximate analogues of well known Net-SNMP snmp* tools
command line options are shown. That may help those readers who, by chance
are familiar with Net-SNMP tools, better understanding what example code doe

Here's a quick example on a simple SNMP GET by high-level API:

.. include:: /../../examples/hlapi/v1arch/asyncore/manager/cmdgen/v2c-get.py
   :start-after: options:
   :end-before: Functionally

.. literalinclude:: /../../examples/hlapi/v1arch/asyncore/manager/cmdgen/v2c-get.py
   :start-after: """#
   :language: python

.. toctree::

   /examples/hlapi/v1arch/asyncore/manager/cmdgen/snmp-versions
   /examples/hlapi/v1arch/asyncore/manager/cmdgen/modifying-variables
   /examples/hlapi/v1arch/asyncore/manager/cmdgen/walking-operations
   /examples/hlapi/v1arch/asyncore/manager/cmdgen/table-operations
   /examples/hlapi/v1arch/asyncore/manager/cmdgen/mib-tweaks
   /examples/hlapi/v1arch/asyncore/manager/cmdgen/transport-tweaks
   /examples/hlapi/v1arch/asyncore/manager/cmdgen/advanced-topics

The following code sends SNMP TRAP:

   .. include:: /../../examples/hlapi/v1arch/asyncore/agent/ntforg/generic-v1-trap.py
      :start-after: options:
      :end-before: Functionally

   .. literalinclude:: /../../examples/hlapi/v1arch/asyncore/agent/ntforg/generic-v1-trap.py
      :start-after: """#
      :language: python

More examples on Notification Originator API usage follow.

.. toctree::

   /examples/hlapi/v1arch/asyncore/agent/ntforg/common-notifications
   /examples/hlapi/v1arch/asyncore/agent/ntforg/evaluating-notification-type
   /examples/hlapi/v1arch/asyncore/agent/ntforg/advanced-topics

More sophisticated SNMP operations can still be performed with
PySNMP via its Native API to Standard SNMP Applications.
