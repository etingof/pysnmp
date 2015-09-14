
Getting peer address information
--------------------------------

Q. How do I find out peer transport address or security information within 
   my receiving app (CommandResponder or Notification Receiver)?

A. SNMP architecture forces you to distinguish communicating entities only 
   on the basis of their community names (SNMPv1/v2c) or 
   ContextEngineId/ContextName pair (SNMPv3). 
   
   In other words, if one SNMP Manager should anyhow differ from another, 
   then they should use distinct community names or SNMP contexts. 
   Transport information should never be used for the identification purposes,
   as in some cases it proves to be unreliable (cases include NAT device or 
   a proxy in the middle, not to mention address spoofing).

   As practice reveals, even perfect design does not always cope well with 
   the imperfect world. So we had to pinch a logic hole from the scope of an 
   SNMP app down to transport layer. Now with the 
   getTransportInfo(stateReference) method call you could get peer transport 
   information upon receiving its SNMP message.

.. code-block:: python

    # Callback function for receiving notifications
    def cbFun(snmpEngine,
              stateReference,
              contextEngineId, contextName,
              varBinds,
              cbCtx):
        transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
