#!/usr/bin/python

import struct
from utils import *

class HandshakeMessage(object):

    # Message types
    HelloRequest = 0	
    ClientHello = 1	
    ServerHello = 2	
    NewSessionTicket = 4	
    Certificate = 11	
    ServerKeyExchange = 12	
    CertificateRequest = 13	
    ServerHelloDone = 14	
    CertificateVerify = 15	
    ClientKeyExchange = 16	
    Finished = 20	
    CertificateStatus = 22

    message_types = {
        0: 'HelloRequest',
        1: 'ClientHello',
        2: 'ServerHello',
        4: 'NewSessionTicket',
        11: 'Certificate',
        12: 'ServerKeyExchange',
        13: 'CertificateRequest',
        14: 'ServerHelloDone',
        15: 'CertificateVerify',
        16: 'ClientKeyExchange',
        20: 'Finished',
        22: 'CertificateStatus'
    }

    def __init__(self):
        self.bytes = ''

    def message_type(self):
        return ord(self.bytes[0])

    def message_length(self):
        h,l = struct.unpack('!BH', self.bytes[1:4])
        return l + (h << 16)

    def version(self):
        ver, = struct.unpack('!H', self.bytes[4:6])
        return ver

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

    @classmethod
    def from_bytes(cls, bytes):
        if ord(bytes[0]) == HandshakeMessage.ClientHello:
            self = ClientHelloMessage()
        elif ord(bytes[0]) == HandshakeMessage.CertificateStatus:
            self = CertificateStatusMessage()
        elif ord(bytes[0]) == HandshakeMessage.ServerHello:
            self = ServerHelloMessage()
        elif ord(bytes[0]) == HandshakeMessage.ServerKeyExchange:
            self = ServerKeyExchangeMessage()
        elif ord(bytes[0]) == HandshakeMessage.Certificate:
            self = CertificateMessage()
        else:
            self = cls()
        self.bytes = bytes
        return self


    def __len__(self):
        return len(self.bytes)


class ClientHelloMessage(HandshakeMessage):
    
    def __init__(self):
        HandshakeMessage.__init__(self)

    def random(self):
        return self.bytes[6:38]

    def session_id_length(self):
        return ord(self.bytes[38])

    # Offset of the list itself, so the length is the 2 bytes /before/
    def cipher_suites_offset(self):
        return self.session_id_length()+41

    def cipher_suites_length(self):
        offset = self.cipher_suites_offset()-2
        length, = struct.unpack('!H', self.bytes[offset:offset+2])
        return length

    def cipher_suites(self):
        start = self.cipher_suites_offset()
        length = self.cipher_suites_length()
        offset = 0
        suites = []
        while True:
            suite, = struct.unpack('!H', self.bytes[start+offset:start+offset+2])
            suites += [suite]
            offset += 2
            if offset >= length:
                break

        return suites

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
            exts = ''
            for extension in extensions:
                exts += extension.bytes
            ext = struct.pack('!H', len(exts))
            ext += exts
        else:
            ext = struct.pack('!H', 0)
    
        message = struct.pack('!H32sB%ds%ds%ds' % (len(ciphers), len(compression), len(ext)),
                              client_version,
                              random,
                              0, # sessionid length,
                              ciphers,
                              compression,
                              ext)
        
        return HandshakeMessage.create(HandshakeMessage.ClientHello, message)


class ClientHelloMessage3(HandshakeMessage):
    '''
    SSL3 version of the client hello. This one doesn't include the extensions
    at all.
    '''
    
    def __init__(self):
        HandshakeMessage.__init__(self)
        
    @classmethod
    def create(cls, client_version, random,
               cipher_suites=[], session_id=None,
               compression_methods=[]):
        
        ciphers = struct.pack('!H%dH' % len(cipher_suites),
                              2*len(cipher_suites), *cipher_suites)
    
        if compression_methods:
            raise NotImplementedError()
        else:
            compression = struct.pack('BB', 1, 0)
                
        message = struct.pack('!H32sB%ds%ds' % (len(ciphers), len(compression)),
                              client_version,
                              random,
                              0, # sessionid length,
                              ciphers,
                              compression)
        
        return HandshakeMessage.create(HandshakeMessage.ClientHello, message)


class CertificateMessage(HandshakeMessage):

    def __init__(self):
        HandshakeMessage.__init__(self)

    @classmethod
    def create(cls, certificates=[]):
        certs = ''

        for cert in certificates:
            cert_bytes = struct.pack('!BH%ds' % len(cert), len(cert) >> 16, len(cert), cert)
            certs += cert_bytes

        message = struct.pack('!BH%ds' % len(certs), len(certs) >> 16, len(certs), certs)

        return HandshakeMessage.create(HandshakeMessage.Certificate, message)


class ServerHelloMessage(HandshakeMessage):

    def __init__(self):
        HandshakeMessage.__init__(self)

    def server_version(self):
        ver, = struct.unpack('!H', self.bytes[4:6])
        return ver

    def cipher_suite_offset(self):
        # header + ver + random
        offset = 4 + 2 + 32
        session_id_len, = struct.unpack('B', self.bytes[offset:offset+1])
        return offset+session_id_len+1

    def cipher_suite(self):
        suite, = struct.unpack('!H', self.bytes[self.cipher_suite_offset():self.cipher_suite_offset()+2])
        return suite

    def has_extensions(self):
        compression_len, = struct.unpack('B',
                                         self.bytes[self.cipher_suite_offset()+2:self.cipher_suite_offset()+3])
        if self.cipher_suite_offset()+compression_len+1 != len(self.bytes):
            return True
        else:
            return False


class ServerKeyExchangeMessage(HandshakeMessage):
    # Note that for now this code assumes that the Kx is DH

    def __init__(self):
        HandshakeMessage.__init__(self)

    def dh_p_len_bytes(self):
        return struct.unpack('!H', self.bytes[4:6])[0]

    def dh_p_len(self):
        return self.dh_p_len_bytes()*8


class CertificateStatusMessage(HandshakeMessage):

    # How far into the handshake the status message itself is
    STATUS_OFFSET = 4
    
    def __init__(self):
        HandshakeMessage.__init__(self)

    def status_type(self):
        return ord(self.bytes[self.STATUS_OFFSET])

    def response_length(self):
        h,length = struct.unpack('!BH',
                                 self.bytes[self.STATUS_OFFSET+1:self.STATUS_OFFSET+4])
        length = length + (h << 16)
        return length

    def response(self):
        return self.bytes[self.STATUS_OFFSET+4:self.response_length()+8]

class TLSExtension(object):

    ServerName = 0
    MaxFragmentLength = 1
    ClientCertificateUrl = 2
    TrustedCAKeys = 3
    TruncateHMAC = 4
    StatusRequest = 5
    EllipticCurves = 10
    ECPointFormats = 11
    Heartbeat = 15
    StatusRequestV2 = 17
    RenegotiationInfo = 65281

    def __init__(self):
        self.bytes = ''

    @classmethod
    def create(cls, extension_type, data, length=-1):
        self = cls()

        if length < 0:
            length = len(data)

        self.bytes = struct.pack('!H%ds' % (len(data)),
                                 extension_type,
                                 data)
        return self

    def __len__(self):
        return len(self.bytes)
