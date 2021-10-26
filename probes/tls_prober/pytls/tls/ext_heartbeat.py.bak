#!/usr/bin/python

from handshake import *

class HeartbeatMessage(object):
    
    # Message types
    HeartbeatRequest = 1
    HeartbeatReponse = 2

    message_types = {
        1: 'HeartbeatRequest',
        2: 'HeartbeatReponse'
    }

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, message_type, payload, length=-1, padding=None):
        self = cls()

        if length < 0:
            length = len(payload)

        if padding is None:
            padding = '*' * 16
        self.bytes = struct.pack('!BH%ds%ds' % (len(payload), len(padding)),
                                 message_type,
                                 length,
                                 payload,
                                 padding)
        return self

    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        self.bytes = bytes
        return self



class HeartbeatExtension(TLSExtension):

    PeerAllowedToSend = 1
    PeerNotAllowedToSend = 2

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls, allowed=PeerAllowedToSend):
        data = struct.pack('!HB', 1, allowed)
        return TLSExtension.create(TLSExtension.Heartbeat, data)
