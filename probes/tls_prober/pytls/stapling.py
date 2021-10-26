#!/usr/bin/python

import sys
import socket
import logging
from optparse import OptionParser
import subprocess

from tls import *

def make_hello():
    status_extension = StatusRequestExtension.create()

    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      [TLS_RSA_WITH_RC4_128_MD5,
                                       TLS_RSA_WITH_RC4_128_SHA,
                                       TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                       TLS_RSA_WITH_AES_128_CBC_SHA,
                                       TLS_RSA_WITH_AES_256_CBC_SHA,
                                       TLS_RSA_WITH_AES_128_CBC_SHA256,
                                       TLS_RSA_WITH_AES_256_CBC_SHA256],
                                      extensions = [ status_extension
                                                     ])
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes

def print_ocsp(ocsp):
    p = subprocess.Popen(['openssl', 'ocsp', '-resp_text', '-noverify', '-respin', '/dev/stdin'],
                         stdout = subprocess.PIPE,
                         stdin = subprocess.PIPE)

    p.stdin.write(ocsp)
    p.stdin.close()

    print(p.stdout.read())

def stapling(f):
    print('Sending Client Hello...')
    f.write(make_hello())

    print('Waiting for Server Hello Done...')
    while True:
        record = read_tls_record(f)

        # Look for server hello message.
        if record.content_type() == TLSRecord.Handshake:
            message = HandshakeMessage.from_bytes(record.message())
            if message.message_type() == HandshakeMessage.ServerHelloDone:
                print('Got server hello done without status...')
                break
            elif message.message_type() == HandshakeMessage.CertificateStatus:
                print('Got certificate status...')
                print('Status type:', message.status_type())
                print_ocsp(message.response())
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

    stapling(f)
 
if __name__ == '__main__':
    main()


