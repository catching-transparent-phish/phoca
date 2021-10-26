#!/usr/bin/python

import struct

class AlertMessage(object):

    # Alert levels
    Warning = 1
    Fatal = 2

    alert_levels = {
        1: 'Warning',
        2: 'Fatal'
    }

    # Alert types
    CloseNotify = 0
    UnexpectedMessage = 10
    BadRecordMac = 20
    DecryptionFailed = 21
    RecordOveflow = 22
    DecompressionFailure = 30
    HandshakeFailure = 40
    NoCertificate = 41
    BadCertificate = 42
    UnsupportedCertificate = 43
    CertificateRevoked = 44
    CertificateExpired = 45
    CertificateUnknown = 46
    IllegalParameter = 47
    UnknownCA = 48
    AccessDenied = 49
    DecodeError = 50
    DecryptError = 51
    ExportRestriction = 60
    ProtocolVersion = 70
    InsufficientSecurity = 71
    InternalError = 80
    InappropriateFallback = 86
    UserCancelled = 90
    NoRenegotiation = 100
    UnsupportedExtension = 110
    CertificateUnobtainable = 111
    UnrecognizedName = 112
    BadCertificateStatusResponse = 113
    BadCertificateHashValue = 114
    UnknownPSKIndentity = 115
    NoApplicationProtocol = 120

    alert_types = {
        0: 'CloseNotify',
        10: 'UnexpectedMessage',
        20: 'BadRecordMac',
        21: 'DecryptionFailed',
        22: 'RecordOveflow',
        30: 'DecompressionFailure',
        40: 'HandshakeFailure',
        41: 'NoCertificate',
        42: 'BadCertificate',
        43: 'UnsupportedCertificate',
        44: 'CertificateRevoked',
        45: 'CertificateExpired',
        46: 'CertificateUnknown',
        47: 'IllegalParameter',
        48: 'UnknownCA',
        49: 'AccessDenied',
        50: 'DecodeError',
        51: 'DecryptError',
        60: 'ExportRestriction',
        70: 'ProtocolVersion',
        71: 'InsufficientSecurity',
        80: 'InternalError',
        86: 'InappropriateFallback',
        90: 'UserCancelled',
        100: 'NoRenegotiation',
        110: 'UnsupportedExtension',
        111: 'CertificateUnobtainable',
        112: 'UnrecognizedName',
        113: 'BadCertificateStatusResponse',
        114: 'BadCertificateHashValue',
        115: 'UnknownPSKIndentity',
        120: 'NoApplicationProtocol'
    }

    def __init__(self):
        self.bytes = ''

    @classmethod
    def from_bytes(cls, bytes):
        self = cls()
        self.bytes = bytes
        return self

    def alert_level(self):
        return self.bytes[0]

    def alert_type(self):
        return self.bytes[1]

    def __str__(self):
        return 'Alert: %s (%d), %s (%d)' \
            % (self.alert_levels.get(self.alert_level(), 'UNKNOWN!'), self.alert_level(),
               self.alert_types.get(self.alert_type(), 'UNKNOWN!'), self.alert_type())
