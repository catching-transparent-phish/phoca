#!/usr/bin/python

import struct

from .handshake import *

class StatusRequestExtension(TLSExtension):

    OCSP = 1

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls, status_type=OCSP):
        # We don't support extensions to the StatusRequest extension
        # So the two lengths are 0
        data = struct.pack('!HBHH', 5, status_type, 0, 0)
        return TLSExtension.create(TLSExtension.StatusRequest, data)
