import struct
# from cipherSuites import *

class HandshakeMessage(object):

    # Message types
    ClientHello = 1

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, message_type, message, length=-1):
        self = cls()

        if length < 0:
            length = len(message)

        self.bytes = struct.pack('!BBH%ds' % (len(message)),
                                 message_type,
                                 length >> 16,
                                 length,
                                 message)

        return self

class ClientHelloMessage(HandshakeMessage):

    def __init__(self):
        HandshakeMessage.__init__(self)

    @classmethod
    def create(cls, client_version, random,
               cipher_suites=[], session_id=None,
               compression_methods=[], extensions=[]):

        ciphers = struct.pack('!H%dH' % len(cipher_suites),
                              2*len(cipher_suites), *cipher_suites)

        if compression_methods:
            raise NotImplementedError()
        else:
            compression = struct.pack('BB', 1, 0)

        if extensions:
            exts = b''
            for extension in extensions:
                exts += extension.bytes
            ext = struct.pack('!H', len(exts))
            ext += exts
        else:
            ext = struct.pack('!H', 0)

        message = struct.pack(b'!H32sB%ds%ds%ds%ds' % (len(session_id), len(ciphers), len(compression), len(ext)),
                              client_version,
                              random,
                              len(session_id), # sessionid length,
                              session_id,
                              ciphers,
                              compression,
                              ext)

        return HandshakeMessage.create(HandshakeMessage.ClientHello, message)

class TLSRecord(object):

    # Content types
    Handshake = 0x16

    # TLS versions
    SSL3 = 0x0300
    TLS1_0 = 0x0301
    TLS1_1 = 0x0302
    TLS1_2 = 0x0303
    TLS1_3 = 0x0304


    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, content_type, version, message, length=-1):
        self = cls()

        if length < 0:
            length = len(message)

        if(type(message) == str):
            message = str.encode(message)

        self.bytes = struct.pack(b'!BHH%ds' % (length),
                                 content_type,
                                 version,
                                 length,
                                 message)
        return self
