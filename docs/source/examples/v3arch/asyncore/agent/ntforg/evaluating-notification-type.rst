.. toctree::
   :maxdepth: 2

Evaluating NOTIFICATION-TYPE
----------------------------

SNMP SMI defines notifications as a TRAP or INFORM PDU containing
the indication of type (snmpTrapOID) and a set of MIB variables
(Managed Objects Instances) fetched from Agent's MIB at the moment
of notification.

Consequently, sending specific NOTIFICATION-TYPE implies including certain
set of OIDs into PDU. PySNMP offers this facility through NotificationType
class.

.. include:: /../../examples/v3arch/asyncore/agent/ntforg/v2c-trap-with-notification-objects.py
   :start-after: """
   :end-before: """#

.. literalinclude:: /../../examples/v3arch/asyncore/agent/ntforg/v2c-trap-with-notification-objects.py
   :start-after: """#
   :language: python

:download:`Download</../../examples/v3arch/asyncore/agent/ntforg/v2c-trap-with-notification-objects.py>` script.


See also: :doc:`library reference </docs/api-reference>`.
