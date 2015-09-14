
Listening on multiple network interfaces
----------------------------------------

Q. I need my receiving entity (CommandResponder or Notification Receiver) 
   to listen for SNMP messages on multiple network interfaces. How do 
   I do that with pysnmp?

A. Simply register multiple network transports with your SNMP engine. 
   Each transport would be bound to an individual local transport 
   endpoint (for instance, IP address & UDP port pair).

.. code-block:: python

    # Security setup would follow
    ...
    # Setup first transport endpoint
    config.addSocketTransport(
        snmpEngine,
        udp.domainName + (1,),
        udp.UdpSocketTransport().openServerMode(('127.0.0.1', 162))
    )

    # Setup second transport endpoint
    config.addSocketTransport(
        snmpEngine,
        udp.domainName + (2,),
        udp.UdpSocketTransport().openServerMode(('192.168.1.1', 162))
    )
    # Receiver callback function implementation and Dispatcher invocation
    # would follow
    ...

   Notice extended transport domain specification (udp.domainName) in 
   the code above. There we register each transport endpoint under distinct 
   OID, however always within the canonical transport domain OID.
