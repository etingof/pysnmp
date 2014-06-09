from pyasn1.compat.octets import null

class ContextData:
    def __init__(self, contextEngineId=None, contextName=null):
        self.contextEngineId = contextEngineId
        self.contextName = contextName

    def __repr__(self):
        return '%s(contextEngineId=%r, contextName=%r)' % (
            self.__class__.__name__, self.contextEngineId, self.contextName
        )
