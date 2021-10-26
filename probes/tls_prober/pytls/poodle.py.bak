#!/usr/bin/python

import sys
import socket
import select
import logging
from optparse import OptionParser

from tls import *

# All SSL3 block ciphers
cbc_ciphers = [
    TLS_NULL_WITH_NULL_NULL,
    TLS_RSA_WITH_NULL_MD5,
    TLS_RSA_WITH_NULL_SHA,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_RSA_WITH_IDEA_CBC_SHA,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_RSA_WITH_DES_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_DSS_WITH_DES_CBC_SHA,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_RSA_WITH_DES_CBC_SHA,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_DSS_WITH_DES_CBC_SHA,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_RSA_WITH_DES_CBC_SHA,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_anon_WITH_DES_CBC_SHA,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
    TLS_KRB5_WITH_DES_CBC_SHA,
    # These ones shouldn't be used for SSL3, but some servers seem to
    # need them for us to be able to connect.
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA
]


def process_response(sock):
    connected_ok = True
    got_done = False
    
    while True:
        # Check if there is anything following the server done
        if got_done:
            # If no data then we're done (the server hasn't sent anything further)
            # we allow 500ms to give the followup time to arrive
            if not select.select([sock.fileno(),],[],[],0.5)[0]:
                break

        record = read_tls_record(sock)
        
        if record.content_type() == TLSRecord.Handshake:
            messages = record.handshake_messages()

            for message in messages:
                if message.message_type() == message.ServerHello:
                    logging.debug('handshake:%s(%x)|', message.message_types[message.message_type()], message.server_version())
                    if message.cipher_suite() not in cbc_ciphers:
                        # Crappy Vigor routers only support RC4-MD5 and ignore the client's cipher list
                        print 'Server ignored our cipher list and used %s' % cipher_suites[message.cipher_suite()]
                        print 'The results for this server cannot be trusted (much like the server)'
                        sys.exit(1)
                else:
                    logging.debug('handshake:%s|', message.message_types[message.message_type()])

                if message.message_type() == HandshakeMessage.ServerHelloDone:
                    got_done = True

                if got_done:
                    continue

        elif record.content_type() == TLSRecord.Alert:
            alert = AlertMessage.from_bytes(record.message())

            if alert.alert_level() == AlertMessage.Fatal:
                logging.debug('alert:%s:fatal|', alert.alert_types[alert.alert_type()])
                connected_ok = False
                break
            else:
                logging.debug('alert:%s:warning|', alert.alert_types[alert.alert_type()])
        else:
            if record.content_types.has_key(record.content_type()):
                logging.debug('record:%s|', record.content_types[record.content_type()])
            else:
                logging.debug('record:type(%x)|', record.content_type())

        if got_done:
            break

    return connected_ok


def make_hello(include_scsv):
    ciphers = cbc_ciphers[:] # Deep copy
    if include_scsv:
        ciphers += [TLS_FALLBACK_SCSV]

    hello = ClientHelloMessage3.create(TLSRecord.SSL3,
                                       '01234567890123456789012345678901',
                                       ciphers)
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.SSL3,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def fallback_scsv(target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.info('Connecting with SSL3 (no SCSV)...')

    s.connect((target, port))
    f = s.makefile('rw', 0)
    f = LoggedFile(f)

    f.write(make_hello(False))
    ssl3_no_scsv = process_response(f)

    if not ssl3_no_scsv:
        print 'Not affected'
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logging.info('Connecting with SSL3 (with SCSV)...')

    s.connect((target, port))
    f = s.makefile('rw', 0)
    f = LoggedFile(f)

    try:
        f.write(make_hello(True))
        ssl3_with_scsv = process_response(f)
    except IOError, e:
        print 'Refused to accept fallback connection'
        return

    if ssl3_with_scsv:
        print 'SSL3 and no fallback support'
    else:
        print 'SSL3 with fallback support'


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
 
    fallback_scsv(args[0], opts.port)


if __name__ == '__main__':
    main()
