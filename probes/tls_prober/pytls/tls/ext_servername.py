#!/usr/bin/python

import struct

from .handshake import *
from .utils import *

class ServerNameExtension(TLSExtension):

    HostName = 0

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls, hostname, hostnames=[], name_type=HostName):

        if len(hostnames) == 0:
            hostnames = [hostname]

        name_list = b''
        for hostname in hostnames:
            name = struct.pack(b'!BH%ds' % (len(hostname)),
                               name_type,
                               len(hostname),
                               str.encode(hostname))
            name_list += name


        data = struct.pack('!HH%ds' % (len(name_list)),
                           len(name_list) + 2,
                           len(name_list),
                           name_list)
        #data = struct.pack('!HHBH%ds' % len(hostname),
        #                   len(hostname) + 5, name_length+3, name_type, name_length, hostname)

        #hexdump(data)
        return TLSExtension.create(TLSExtension.ServerName, data)
