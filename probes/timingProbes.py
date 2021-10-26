# Snippets taken from https://gist.github.com/fffaraz/57144833c6ef8bd9d453
import socket, sys, time, random, ssl, string
from struct import *
from networking.tcp.TCPSegment import TCPSYNSegment
from networking.tls.messages import *
from networking.tls.extensions import *
from networking.tls.cipherSuites import CIPHER_SUITES, SIGNATURE_ALGORITHMS
from urllib.parse import urlparse
from tldextract import extract

class TimingProbe:

    def __init__(self, domain, http_port = 80, https_port = 443):
        self.domain = domain
        self.rawSocket = False
        self.sslSocket = False
        self.http_port = http_port
        self.https_port = https_port

        if('//' not in domain):
            self.site = 'https://' + domain
        else:
            self.site = domain
        self.fullDomain, self.primaryDomain, self.port, self.path = TimingProbe.parseURL(self.site)

        try:
            self.dest_ip = socket.gethostbyname(self.fullDomain)
        except:
            self.dest_ip = None

    @staticmethod
    def parseURL(url):
        parts = urlparse(url)

        fullDomain = parts.netloc
        if(':' in fullDomain):
            fullDomain = fullDomain.split(':')[0]
        port = parts.port
        path = parts.path

        tsd, td, tsu = extract(fullDomain)
        primaryDomain = td + '.' + tsu

        return fullDomain, primaryDomain, port, path

    def connect(self, rawSocket=False, sslSocket=False, timeout=2):
        self.socket = None

        if(rawSocket):
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.socket.settimeout(timeout)
            self.rawSocket = True
            # tell kernel not to put in headers, since we are providing it
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        elif(sslSocket):
            self.sslSocket = True
            context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
            context.verify_mode = ssl.CERT_NONE # disable cert. validation
            context.check_hostname = False  # disable host name checking
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
            self.socket = context.wrap_socket(s, server_hostname = self.fullDomain, do_handshake_on_connect=False) # wrap socket into TLS context
            self.socket.settimeout(timeout)
            self.socket.connect((self.dest_ip, self.dest_port)) # TLS socket connection
        else:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.socket.connect((self.dest_ip, self.dest_port))

    def disconnect(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self.socket.close()

    def getRandomString(self, stringLength=10):
        """Generate a random string of fixed length """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))

    def test(self, payload, rawSocket=False, sslSocket=False, n=1, timeout=2):
        results = []

        for i in range(0, n):
            try:
                self.connect(rawSocket=rawSocket, sslSocket=sslSocket, timeout=timeout)
            except:
                results.append(None)
                continue

            perf = None
            try:
                if(self.rawSocket):
                    startTime = time.time()
                    self.socket.sendto(payload, (self.dest_ip , self.dest_port))
                    msg = self.socket.recv(1024)
                    perf = time.time() - startTime
                elif(self.sslSocket and payload==None):
                    startTime = time.time()
                    self.socket.do_handshake()
                    perf = time.time() - startTime
                else:
                    startTime = time.time()
                    self.socket.send(payload)
                    msg = self.socket.recv(1024)
                    perf = time.time() - startTime
            except (TimeoutError, ConnectionResetError, socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as e:
                pass
            finally:
                self.disconnect()
                results.append(perf)

        results = [result for result in results if result != None]
        if(len(results) == 0):
            return -1
        return min(results)

class tcpSYNTiming(TimingProbe):

    def test(self, n=1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            self.source_ip, self.source_port = s.getsockname()
            self.dest_port = self.https_port
        except Exception as e:
            return -1
        finally:
            s.close()

        try:
            tcpSynPacket = TCPSYNSegment(self.source_ip, self.source_port, self.dest_ip, self.dest_port).create()
        except:
            return -1
        return super().test(tcpSynPacket, rawSocket=True, n=n)

class tlsClientHelloTiming(TimingProbe):

    def make_client_hello(self):
        extensions = [SignatureAlgorithms.create(SIGNATURE_ALGORITHMS),
                    SupportedVersionsExtension.create(), ECPointFormatsExtension.create(),
                    SupportedGroupsExtension.create(), SessionTicketExtension.create(),
                    EncryptThenMacExtension.create(), ExtendedMasterSecretExtension.create(),
                    PSKKeyExchangeModesExtension.create(), KeyShareExtension.create()]
        if(self.fullDomain != None):
            extensions.append(ServerNameExtension.create(self.fullDomain))

        hello = ClientHelloMessage.create(TLSRecord.TLS1_2,
                                          bytearray(random.getrandbits(8) for _ in range(32)),
                                          CIPHER_SUITES,
                                          extensions=extensions,
                                          session_id=bytearray(random.getrandbits(8) for _ in range(32)))

        record = TLSRecord.create(content_type=TLSRecord.Handshake,
                                  version=TLSRecord.TLS1_0,
                                  message=hello.bytes)

        return record.bytes

    def test(self, n=1):
        self.dest_port = self.https_port
        clientHelloMessage = self.make_client_hello()
        return super().test(clientHelloMessage, n=n)

class tlsClientHelloErrorTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.https_port
        clientHelloMessage = b'\xcfU"\xf1\';\x8c\xd8\xb0W)7+\xbc\xedN\x07\xc9*\xc9d\xdb\x19@M\x81-\x980P%\x8a'
        return super().test(clientHelloMessage, timeout=2, n=n)

# https://stackoverflow.com/questions/52697613/measuring-tls-handshake-performance-time-in-python
class tlsHandshakeTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.https_port
        return super().test(None, sslSocket=True, n=n)

# https://stackoverflow.com/questions/54393599/measuring-performance-time-for-tls-handshake
class httpsGetRequestTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.https_port
        getRequest = str.encode('GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n' % (self.getRandomString(), self.fullDomain))
        return super().test(getRequest, sslSocket=True, n=n)

class httpGetRequestTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.http_port
        getRequest = str.encode('GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n' % (self.getRandomString(), self.fullDomain))
        return super().test(getRequest, n=n)

# https://stackoverflow.com/questions/54393599/measuring-performance-time-for-tls-handshake
class httpsGetRequestErrorTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.https_port
        getRequest = str.encode('ERROR /%s HTTP/1.1\r\nHost: %s\r\n\r\n' % (self.getRandomString(), self.fullDomain))
        return super().test(getRequest, sslSocket=True, n=n)

class httpGetRequestErrorTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.http_port
        getRequest = str.encode('ERROR /%s HTTP/1.1\r\nHost: %s\r\n\r\n' % (self.getRandomString(), self.fullDomain))
        return super().test(getRequest, n=n)

# https://stackoverflow.com/questions/54393599/measuring-performance-time-for-tls-handshake
class httpsGetRequestNoHostHeaderTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.https_port
        getRequest = str.encode('GET /%s HTTP/1.1\r\n\r\n' % (self.getRandomString()))
        return super().test(getRequest, sslSocket=True, n=n)

class httpGetRequestNoHostHeaderTiming(TimingProbe):

    def test(self, n=1):
        self.dest_port = self.http_port
        getRequest = str.encode('GET /%s HTTP/1.1\r\n\r\n' % (self.getRandomString()))
        return super().test(getRequest, n=n)
