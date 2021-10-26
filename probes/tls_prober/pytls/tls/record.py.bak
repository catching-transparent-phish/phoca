#!/usr/bin/python

import struct
import logging

from alert import *
from handshake import *

class TLSRecord(object):

    # Content types
    ChangeCipherSpec = 0x14
    Alert = 0x15
    Handshake = 0x16
    Application = 0x17
    Heartbeat = 0x18

    content_types = {
        0x14: 'ChangeCipherSpec',
        0x15: 'Alert',
        0x16: 'Handshake',
        0x17: 'Application',
        0x18: 'Heartbeat'
    }

    # TLS versions
    SSL3 = 0x0300
    TLS1_0 = 0x0301
    TLS1_1 = 0x0302
    TLS1_2 = 0x0303
    TLS1_3 = 0x0304

    tls_versions = {
        0x0300: 'SSL3',
        0x0301: 'TLS1_0',
        0x0302: 'TLS1_1',
        0x0303: 'TLS1_2',
        0x0304: 'TLS1_3'
    }

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, content_type, version, message, length=-1):
        self = cls()

        # TODO: support mac=None, padding=None

        if length < 0:
            length = len(message)

        self.bytes = struct.pack('!BHH%ds' % (length),
                                 content_type,
                                 version,
                                 length,
                                 message)

        return self
     
    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        self.bytes = bytes
        return self

    def content_type(self):
        return ord(self.bytes[0])

    def version(self):
        version, = struct.unpack('!H', self.bytes[1:3])
        return version

    def message_length(self):
        length, = struct.unpack('!H', self.bytes[3:5])
        return length

    def message(self):
        return self.bytes[5:self.message_length()+5]

    def handshake_messages(self):
        if self.content_type() != self.Handshake:
            raise Exception('Not a Handshake record')

        messages = []

        # A single handshake record can contain multiple handshake messages
        processed_bytes = 0
        while processed_bytes < self.message_length():
            message = HandshakeMessage.from_bytes(self.message()[processed_bytes:])
            processed_bytes += message.message_length() + 4
            messages += [message]

        return messages

    def __len__(self):
        return len(self.bytes)

#
# Utilities for processing responses
#

def read_tls_record(f):
    logger = logging.getLogger('pytls')

    hdr = f.read(5)
    if hdr == '':
        raise IOError('Unexpected EOF receiving record header - server closed connection')

    typ, ver, ln = struct.unpack('>BHH', hdr)
    logger.debug('%d\t0x%x\t%d', typ, ver, ln)

    pay = f.read(ln)
    if pay == '':
        raise IOError('Unexpected EOF receiving record payload - server closed connection')


    logger.debug(' ... received message: type = %d (%s), ver = %04x, length = %d',
                 typ, TLSRecord.content_types.get(typ, 'UNKNOWN!'), ver, len(pay))

    if typ == TLSRecord.Handshake:
        logger.debug('>>> Handshake message: %s', HandshakeMessage.message_types.get(ord(pay[0]), 'UNKNOWN!'))
    elif typ == TLSRecord.Alert:
        logger.debug('>>> Alert message: %s', AlertMessage.alert_types.get(ord(pay[1]), 'UNKNOWN!'))

    return TLSRecord.from_bytes(hdr+pay)
