import sys, requests, json, os, ssl, socket, asyncio
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urlparse
from tldextract import extract

sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'tls_prober'))
from tls_prober import prober, probe_db

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class FeatureProbe:

    def __init__(self, site, http_port = 80, https_port = 443):
        if('//' not in site):
            self.site = 'https://' + site
        else:
            self.site = site

        self.http_port = http_port
        self.https_port = https_port

        self.fullDomain, self.primaryDomain, self.port, self.path = FeatureProbe.parseURL(self.site)

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

class TLSVersions(FeatureProbe):

    def test(self):
        results = {"SSLv2" : None, "SSLv3" : None, "TLSv1" : None, "TLSv1.1" : None, "TLSv1.2" : None,
                    "TLSv1.3" : None}

        for tlsVersion in results.keys():
            results[tlsVersion] = self.testTLSVersion(tlsVersion)

        return results

    def testTLSVersion(self, version):
        versionFlags = {"SSLv2" : ssl.OP_NO_SSLv2, "SSLv3" : ssl.OP_NO_SSLv3, "TLSv1" : ssl.OP_NO_TLSv1,
                "TLSv1.1" : ssl.OP_NO_TLSv1_1, "TLSv1.2" : ssl.OP_NO_TLSv1_2, "TLSv1.3" : ssl.OP_NO_TLSv1_3}

        context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)
        context.verify_mode = ssl.CERT_NONE # disable cert. validation
        context.check_hostname = False  # disable host name checking
        context.options &= ~ssl.OP_NO_SSLv3

        # Disable all TLS versions and reenable the one that we do want
        blackListVersions = ssl.OP_NO_TLSv1_3 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
        blackListVersions &= ~versionFlags[version]
        context.options |= blackListVersions

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # create socket
        wrappedSocket = context.wrap_socket(s, server_hostname = self.fullDomain, do_handshake_on_connect=True) # wrap socket into TLS context
        wrappedSocket.settimeout(2)
        try:
            wrappedSocket.connect((self.fullDomain, 443)) # TLS socket connection
            acceptedVersion = wrappedSocket.version()
            return acceptedVersion == version
        except (ssl.SSLError):
            return False
        except (ConnectionResetError, socket.gaierror, Exception):
            return None
        finally:
            wrappedSocket.close()

class TLSLibrary(FeatureProbe):

    def test(self):
        results = prober.probe(self.fullDomain, self.https_port, 'auto', None)
        matches = probe_db.find_matches(results)
        results = {key:value for (key,value) in matches}
        return results
