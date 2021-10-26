import struct

class TLSExtension(object):

    ServerName = 0
    MaxFragmentLength = 1
    ClientCertificateUrl = 2
    TrustedCAKeys = 3
    TruncateHMAC = 4
    StatusRequest = 5
    SupportedGroups = 10
    ECPointFormats = 11
    SignatureAlgorithms = 13
    Heartbeat = 15
    StatusRequestV2 = 17
    EncryptThenMac = 22
    ExtendedMasterSecret = 23
    SessionTicket = 35
    SupportedVersions = 43
    PSKKeyExchangeModes = 45
    KeyShare = 51
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

class KeyShareExtension(TLSExtension):

    def __init__(self):
        super.__init__(self)

    @classmethod
    def create(cls):

        keyShareEntry = b"\x00\x26\x00\x24\x00\x1d\x00\x20\x80\xcb\xcd\xec\x49\x5d\xeb\x93\x57\x11" \
                        b"\x1f\xab\x02\x2d\xb8\x3c\x72\x96\x9c\x16\x45\x16\xa8\x8d\x18\x2a" \
                        b"\xf1\x48\xa4\xb5\x43\x17"
        return TLSExtension.create(TLSExtension.KeyShare, keyShareEntry)

class PSKKeyExchangeModesExtension(TLSExtension):

    def __init__(self):
        super.__init__(self)

    @classmethod
    def create(cls):

        data = struct.pack('!HBB', 2, 1, 1)

        return TLSExtension.create(TLSExtension.PSKKeyExchangeModes, data)

class ExtendedMasterSecretExtension(TLSExtension):

    def __init__(self):
        super.__init__(self)

    @classmethod
    def create(cls):

        data = struct.pack('!H', 0)

        return TLSExtension.create(TLSExtension.ExtendedMasterSecret, data)

class EncryptThenMacExtension(TLSExtension):

    def __init__(self):
        super.__init__(self)

    @classmethod
    def create(cls):

        data = struct.pack('!H', 0)

        return TLSExtension.create(TLSExtension.EncryptThenMac, data)

class SessionTicketExtension(TLSExtension):

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls, sessionTicket=b''):
        data = struct.pack('!H%ds' % len(sessionTicket),
                            len(sessionTicket),
                            sessionTicket)
        return TLSExtension.create(TLSExtension.SessionTicket, data)

class SupportedGroupsExtension(TLSExtension):

    X25519 = 0x1d
    SECP256R1 = 0x17
    X448 = 0x1e
    SECP521R1 = 0x19
    SECP384R1 = 0x18

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls, supportedGroups=[]):
        if(supportedGroups == []):
            supportedGroups = [cls.X25519, cls.SECP256R1, cls.X448, cls.SECP521R1, cls.SECP384R1]

        group_list = b''
        for supportedGroup in supportedGroups:
            group = struct.pack(b'!H', supportedGroup)
            group_list += group

        data = struct.pack('!HH%ds' % len(group_list),
                            len(group_list) + 2,
                            len(group_list),
                            group_list)

        return TLSExtension.create(TLSExtension.SupportedGroups, data)

class SignatureAlgorithms(TLSExtension):

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls, signatureAlgorithms=[]):

        algo_list = b''
        for algorithm in signatureAlgorithms:
            algo = struct.pack(b'!H', algorithm)
            algo_list += algo

        data = struct.pack('!HH%ds' % (len(algo_list)),
                           len(algo_list) + 2,
                           len(algo_list),
                           algo_list)

        return TLSExtension.create(TLSExtension.SignatureAlgorithms, data)

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

        return TLSExtension.create(TLSExtension.ServerName, data)

class ECPointFormatsExtension(TLSExtension):

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls):
        supported_versions_list = struct.pack(b'!BBB', *(0,1,2))

        data = struct.pack('!HB%ds' % (len(supported_versions_list)),
                            len(supported_versions_list) + 1,
                            len(supported_versions_list),
                           supported_versions_list)

        return TLSExtension.create(TLSExtension.ECPointFormats, data)

class SupportedVersionsExtension(TLSExtension):

    # TLS versions
    SSL3 = 0x0300
    TLS1_0 = 0x0301
    TLS1_1 = 0x0302
    TLS1_2 = 0x0303
    TLS1_3 = 0x0304

    def __init__(self):
        TLSExtension.__init__(self)

    @classmethod
    def create(cls):
        supported_versions = (cls.TLS1_0, cls.TLS1_1, cls.TLS1_2, cls.TLS1_3)

        supported_versions_list = struct.pack(b'!' + b'H'*len(supported_versions), *supported_versions)

        data = struct.pack('!HB%ds' % (len(supported_versions_list)),
                            len(supported_versions_list) + 1,
                            len(supported_versions_list),
                           supported_versions_list)

        return TLSExtension.create(TLSExtension.SupportedVersions, data)
