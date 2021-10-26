#!/usr/bin/python

import sys
import socket
import select
import logging
from optparse import OptionParser

from tls import *

def dump_hello(record):
    print('Record Version:', record.tls_versions[record.version()])

    messages = record.handshake_messages()
    for message in messages:
        logging.debug('handshake:%s|', message.message_types[message.message_type()])

        print('Handshake Version:', record.tls_versions[message.version()])
        if message.message_type() == message.ClientHello:
            print('Session ID Length:', message.session_id_length())
            print('Cipher Suites Length (bytes):', message.cipher_suites_length())
            print('Cipher Suites:')
            for suite in message.cipher_suites():
                print('0x%04x' % suite, cipher_suites.get(suite, 'UNKNOWN'))

def read_hello(f):
    record = read_tls_record(f)
    if record.content_type() == TLSRecord.Handshake:
        dump_hello(record)
    else:
        raise Exception('Unexpected message type %s', message.message_types[message.message_type()])

def main():
    options = OptionParser(usage='%prog server [options]',
                           description='Test for Python SSL')
    options.add_option('-p', '--port',
                       type='int', default=4433,
                       help='TCP port to listen on (default: 4433)')
    options.add_option('-d', '--debug', action='store_true', dest='debug',
                       default=False,
                       help='Print debugging messages')

    opts, args = options.parse_args()

    if opts.debug:
        logging.basicConfig(level=logging.DEBUG)
 
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    print('Binding...')
    s.bind(('0.0.0.0', opts.port))

    s.listen(1)
    while True:
        conn, addr = s.accept()
        print('Connection from', addr)
        f = conn.makefile('rw', 0)
        f = LoggedFile(f)
        read_hello(f)

if __name__ == '__main__':
    main()
