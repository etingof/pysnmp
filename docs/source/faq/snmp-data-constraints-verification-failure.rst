
SNMP data constraints verification error
----------------------------------------

Q. Will PySNMP Manager verify the values it sends to and receives from 
   a distant Agent against local MIB constraints?

A. Yes, it can do that. The Manager will verify the values you pass to SET
   request against a MIB if:

   The values are not already PyASN1 objects but some basic Python types 
   (like integer or string). You tell PySNMP engine to load appropriate 
   MIB where it could lookup the constraints (via the use of MibVariable)
   So, the following code fragment makes PySNMP engine loading SNMPv2-MIB
   and verifying that the 'new system name' value satisfies sysName 
   constraints (if any).

.. code-block:: python

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.setCmd(
        cmdgen.CommunityData('public'),
        cmdgen.UdpTransportTarget(('localhost', 161)),
        ( cmdgen.MibVariable('SNMPv2-MIB', 'sysName', 0), 'new system name' )
    )

To verify the response values, you should pass at least lookupValues flag 
to CommandGenerator \*cmd() method you use. In the following example 
PySNMP will make sure that Agent-supplied value for SNMPv2-MIB::sysName 
Managed Object satisfies MIB constraints (if any).

.. code-block:: python

    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        cmdgen.CommunityData('public'),
        cmdgen.UdpTransportTarget(('localhost', 161)),
        cmdgen.MibVariable('SNMPv2-MIB', 'sysName', 0),
        lookupValues=True
    )

In case of constraint violation, a PySNMP exception will be raised.
