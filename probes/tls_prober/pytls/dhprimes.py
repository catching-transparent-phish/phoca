#!/usr/bin/python

import sys
import socket
import logging
from optparse import OptionParser
import subprocess

from tls import *

def make_hello():
    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      [TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                       TLS_DH_RSA_WITH_DES_CBC_SHA,
                                       TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
                                       TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
                                       TLS_DHE_RSA_WITH_DES_CBC_SHA,
                                       TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
                                       TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
                                       TLS_DH_anon_WITH_RC4_128_MD5,
                                       TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
                                       TLS_DH_anon_WITH_DES_CBC_SHA,
                                       TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
                                       TLS_DH_RSA_WITH_AES_128_CBC_SHA,
                                       TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                                       TLS_DH_anon_WITH_AES_128_CBC_SHA,
                                       TLS_DH_RSA_WITH_AES_256_CBC_SHA,
                                       TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                                       TLS_DH_anon_WITH_AES_256_CBC_SHA,
                                       TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
                                       TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
                                       TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
                                       TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
                                       TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
                                       TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
                                       TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
                                       TLS_DH_anon_WITH_AES_128_CBC_SHA256,
                                       TLS_DH_anon_WITH_AES_256_CBC_SHA256,
                                       TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
                                       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
                                       TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
                                       TLS_DH_RSA_WITH_SEED_CBC_SHA,
                                       TLS_DHE_RSA_WITH_SEED_CBC_SHA,
                                       TLS_DH_anon_WITH_SEED_CBC_SHA,
                                       TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                       TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                                       TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
                                       TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
                                       TLS_DH_anon_WITH_AES_128_GCM_SHA256,
                                       TLS_DH_anon_WITH_AES_256_GCM_SHA384,
                                       TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                                       TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
                                       TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
                                       TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                                       TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
                                       TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
                                       TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
                                       TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
                                       TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
                                       TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
                                       TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
                                       TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
                                       TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
                                       TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
                                       TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
                                       TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
                                       TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
                                       TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
                                       TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                                       TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                                       TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
                                       TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
                                       TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
                                       TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
                                       TLS_DHE_RSA_WITH_AES_128_CCM,
                                       TLS_DHE_RSA_WITH_AES_256_CCM,
                                       TLS_DHE_RSA_WITH_AES_128_CCM_8,
                                       TLS_DHE_RSA_WITH_AES_256_CCM_8,
                                       TLS_PSK_DHE_WITH_AES_128_CCM_8,
                                       TLS_PSK_DHE_WITH_AES_256_CCM_8])
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def dhprimes(f):
    print('Sending Client Hello...')
    f.write(make_hello())

    print('Waiting for Server Key Exchange...')
    while True:
        record = read_tls_record(f)

        # Look for server hello message.
        if record.content_type() == TLSRecord.Handshake:
            message = HandshakeMessage.from_bytes(record.message())
            if message.message_type() == HandshakeMessage.ServerHelloDone:
                print('Got server hello done without key exchange...')
                break
            elif message.message_type() == HandshakeMessage.ServerKeyExchange:
                print('Got server key exchange, prime p length is', message.dh_p_len())
                break
        elif record.content_type() == TLSRecord.Alert:
            alert = AlertMessage.from_bytes(record.message())
            print(alert)
            if alert.alert_level() == AlertMessage.Fatal:
                raise IOError('Server sent a fatal alert')
        else:
            print('Record received type %d' % (record.content_type()))

    
def main():
    options = OptionParser(usage='%prog server [options]',
                           description='Test for Python SSL')
    options.add_option('-p', '--port',
                       type='int', default=443,
                       help='TCP port to test (default: 443)')
    options.add_option('-d', '--debug', action='store_true', dest='debug',
                       default=False,
                       help='Print debugging messages')

    opts, args = options.parse_args()

    if len(args) < 1:
        options.print_help()
        return

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Connecting...')

    s.connect((args[0], opts.port))
    f = s.makefile('rw', 0)
    f = LoggedFile(f)

    dhprimes(f)
 
if __name__ == '__main__':
    main()


