"""Carrier exceptions"""
from pysnmp import error

class CarrierError(error.PySnmpError): pass
class BadArgumentError(CarrierError): pass
