# Top-level exception class
class PySnmpError(Exception):
    def __init__(self, why=None):
        Exception.__init__(self)
        self.why = why
    def __str__(self): return str(self.why)
    def __repr__(self): return self.__class__.__name__ + '(' + repr(self.why) + ')'
    def __nonzero__(self):
        if self.why: return 1
        else: return 0

class PySnmpVersionError(PySnmpError): pass
