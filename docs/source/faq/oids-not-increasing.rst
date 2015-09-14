
Dealing with OIDs not increasing error
--------------------------------------

Q. I'm walking a particular Agent with the CommandGenerator.nextCmd() 
   and CommandGenerator.bulkCmd() methods. It works for some OIDs, but 
   invariably fails at certain OID with the 'OIDs are not increasing' 
   diagnostics. What does it mean and how do I fix that?

A. The Agent you are talking to seems to be broken. The 'OIDs are not 
   increasing' message means that in the course of fetching OIDs from Agent, 
   Manager receives an OID that is not greater than those used in request.
   Due to the nature of GETNEXT/GETBULK algorithm, passing the same or 
   lesser OID to Manager would result in fetching the same set of OIDs over 
   and over again effectively creating an infinite loop between Manager 
   and Agent so they may never reach the end of MIB. So Manager tries 
   to intervene and prevent loop from happenning.

   If have to work with a broken Agent and prepared some other mean 
   for stopping GETNEXT/GETBULK app at some point, you could set the 
   ignoreNonIncreasingOid option at CommandGenerator class instance 
   to disable OID verification on Manager side.

.. code-block:: python

    cmdGen = cmdgen.CommandGenerator()
    cmdGen.ignoreNonIncreasingOid = True
    errorIndication, errorStatus, errorIndex, varBindTable = cmdGen.bulkCmd(...)

