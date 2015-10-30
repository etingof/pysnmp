
How to implement MIB at the Agent
---------------------------------

Q. How to instantiate static MIB table at my SNMP Agent?

A. You need to create MibScalarInstance class instances and register 
   them with your Agent's SNMP engine (mibBuilder, more specifically).
   Here's an example code for a IP-MIB table:

.. code-block:: python

    # SNMP Agent (AKA CommandResponder) is built around SNMP engine object
    snmpEngine = engine.SnmpEngine()

    # Import table columns
    ( ipAddressAddrType,
      ipAddressAddr,
      ipAddressIfIndex,
      ipAddressType,
      ipAddressPrefix,
      ipAddressOrigin, 
      ipAddressStatus, 
      ipAddressCreated, 
      ipAddressLastChanged, 
      ipAddressRowStatus, 
      ipAddressStorageType ) = snmpEngine.msgAndPduDsp.mibInstrumController
    .mibBuilder.importSymbols(
      'IP-MIB',
      'ipAddressAddrType',
      'ipAddressAddr', 
      'ipAddressIfIndex', 
      'ipAddressType', 
      'ipAddressPrefix',
      'ipAddressOrigin',
      'ipAddressStatus',
      'ipAddressCreated',
      'ipAddressLastChanged', 
      'ipAddressRowStatus', 
      'ipAddressStorageType'
    )

    # Import MibScalarInstance

    MibScalarInstance, = snmpEngine.msgAndPduDsp.mibInstrumController.
    mibBuilder.importSymbols('SNMPv2-SMI', 'MibScalarInstance')

    # Create table columns instances

    _ipAddressAddrType = MibScalarInstance(
        ipAddressAddrType.name, (1, 4, 1, 2, 3, 4),
        ipAddressAddrType.syntax.clone(1)
    )
    _ipAddressAddr = MibScalarInstance(
        ipAddressAddr.name, (1, 4, 1, 2, 3, 4), 
        ipAddressAddr.syntax.clone('1.2.3.4')
    )
    _ipAddressIfIndex = MibScalarInstance(
        ipAddressIfIndex.name, (1, 4, 1, 2, 3, 4), 
        ipAddressIfIndex.syntax.clone(1)
    )
    _ipAddressType = MibScalarInstance(
        ipAddressType.name, (1, 4, 1, 2, 3, 4),
        ipAddressType.syntax.clone(1)
    )
    _ipAddressPrefix = MibScalarInstance(
        ipAddressPrefix.name, (1, 4, 1, 2, 3, 4), 
        ipAddressPrefix.syntax.clone((0,0))
    )
    _ipAddressOrigin = MibScalarInstance(
        ipAddressOrigin.name, (1, 4, 1, 2, 3, 4),
        ipAddressOrigin.syntax.clone(1)
    )
    _ipAddressStatus = MibScalarInstance(
        ipAddressStatus.name, (1, 4, 1, 2, 3, 4),
        ipAddressStatus.syntax.clone(1)
    )
    _ipAddressCreated = MibScalarInstance(
        ipAddressCreated.name, (1, 4, 1, 2, 3, 4), 
        ipAddressCreated.syntax.clone(800)
    )
    _ipAddressLastChanged = MibScalarInstance(
        ipAddressLastChanged.name, (1, 4, 1, 2, 3, 4), 
        ipAddressLastChanged.syntax.clone(600)
    )
    _ipAddressRowStatus = MibScalarInstance(
        ipAddressRowStatus.name, (1, 4, 1, 2, 3, 4), 
        ipAddressRowStatus.syntax.clone(1)
    )
    _ipAddressStorageType = MibScalarInstance(
        ipAddressStorageType.name, (1, 4, 1, 2, 3, 4),
        ipAddressStorageType.syntax
    )

    # add anonymous column instances
    snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.exportSymbols(
        '_IP-MIB',
        _ipAddressAddrType,
        _ipAddressAddr,
        _ipAddressIfIndex,
        _ipAddressType,
        _ipAddressPrefix,
        _ipAddressOrigin,
        _ipAddressStatus,
        _ipAddressCreated,
        _ipAddressLastChanged,
        _ipAddressRowStatus,
        _ipAddressStorageType
        )

    # Command responder code would follow...

Keep in mind that the values of this table row will not change by 
themselves. They basically hold a snapshot of a data set so your 
application may have to update them somehow. For example, an app could 
periodically lookup particular MibScalarInstance by OID at mibBuilder and 
update its "syntax" attribute with a new value.

There are other ways for building MIB tables that represent dynamic 
Managed Objects.
