#!/usr/bin/python

import sys
import socket
import logging
from optparse import OptionParser
import subprocess

from tls import *

def make_hello(name):
    #sni_extension = ServerNameExtension.create('daniel.molkentin.net')
    sni_extension = ServerNameExtension.create(name)
    sni_extension2 = ServerNameExtension.create('x')
    #sni_extension = ServerNameExtension.create(hostname=None, hostnames = [name,'x','y'])

    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      [TLS_RSA_WITH_RC4_128_MD5,
                                       TLS_RSA_WITH_RC4_128_SHA,
                                       TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                       TLS_RSA_WITH_AES_128_CBC_SHA,
                                       TLS_RSA_WITH_AES_256_CBC_SHA,
                                       TLS_RSA_WITH_AES_128_CBC_SHA256,
                                       TLS_RSA_WITH_AES_256_CBC_SHA256],
                                      extensions = [ sni_extension, sni_extension2])
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def server_name(f, name):
    print 'Sending Client Hello...'
    f.write(make_hello(name))

    print 'Waiting for Server Hello Done...'
    while True:
        record = read_tls_record(f)

        # Look for server hello message.
        if record.content_type() == TLSRecord.Handshake:
            message = HandshakeMessage.from_bytes(record.message())
            if message.message_type() == HandshakeMessage.ServerHelloDone:
                print 'Got server hello done...'
                break
            elif message.message_type() == HandshakeMessage.ServerHello:
                # Dump server hello info
                print 'Got server hello...'
                print 'Version:', TLSRecord.tls_versions.get(message.server_version(), 'UNKNOWN!'), \
                    hex(message.server_version())
                print 'Cipher Suite:', cipher_suites.get(message.cipher_suite(), 'UNKNOWN!'), \
                    hex(message.cipher_suite())
                print 'Extensions Present:', message.has_extensions()
        elif record.content_type() == TLSRecord.Alert:
            alert = AlertMessage.from_bytes(record.message())
            print alert
            if alert.alert_level() == AlertMessage.Fatal:
                raise IOError('Server sent a fatal alert')
        else:
            print 'Record received type %d' % (record.content_type())

    
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
    print 'Connecting...'

    s.settimeout(5)
    s.connect((args[0], opts.port))
    f = s.makefile('rw', 0)
    f = LoggedFile(f)

    if len(args) == 2:
        name = args[1]
    else:
        name = args[0]

    server_name(f, name)
 
if __name__ == '__main__':
    main()


