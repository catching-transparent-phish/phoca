#!/usr/bin/python

import sys
import socket
import select
import logging
from base64 import b64decode
from optparse import OptionParser

from tls import *

cert_b64 = \
'MIIDYDCCAkigAwIBAgIBATANBgkqhkiG9w0BAQUFADCBqzEmMCQGA1UEAxMdV2Vz'\
'dHBvaW50IENlcnRpZmljYXRlIFRlc3QgQ0ExEzARBgNVBAgTCkxhbmNhc2hpcmUx'\
'CzAJBgNVBAYTAlVLMR0wGwYJKoZIhvcNAQkBFg5jYUBleGFtcGxlLmNvbTFAMD4G'\
'A1UEChM3V2VzdHBvaW50IENlcnRpZmljYXRlIFRlc3QgUm9vdCBDZXJ0aWZpY2F0'\
'aW9uIEF1dGhvcml0eTAeFw0xMTExMjQxMzA5MTdaFw0yMTExMjExMzA5MTdaMHUx'\
'FDASBgNVBAMTC2V4YW1wbGUuY29tMRMwEQYDVQQIEwpMYW5jYXNoaXJlMQswCQYD'\
'VQQGEwJVSzEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxlLmNvbTEaMBgGA1UE'\
'ChMRU29tZSBvcmdhbmlzYXRpb24wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB'\
'ALk6PGYCD4cpWD1t1eIwUg0RSxEjWjfDPwkXdP5DYVNWi/WWHRcqAHgADlAGkYTr'\
'OHAYLh5rCtH9OESfR8ZUExWnAWsen+j83UjKzFkI9BXjNi+owjiIqaRpi0f0Fkw/'\
'AlYEzqhcfU81SULgEZnO6QAZ13p1Xnb2bbGv6KIjnRazAgMBAAGjSDBGMAkGA1Ud'\
'EwQCMAAwOQYIKwYBBQUHAQEELTArMCkGCCsGAQUFBzABhh1odHRwOi8vb2NzcC5l'\
'eGFtcGxlLmNvbTo4ODg4LzANBgkqhkiG9w0BAQUFAAOCAQEAmKCEGL2UQQA1xgg3'\
'dRJ6g2W62YdQp4R4PrW+su2WdSoAn4Qq4b6Lm8QbfY9baPxqREMZUhMYTG1HvoVT'\
'3x3p6sXqunaeRL5kSf+5CV8xoz5CLm18A5GFSB8myUae/3SBXBusG7b3CBIfE154'\
'MacPvCK8NtFcrScx5T1TYVh5wSm/SE348pBJtJXe16yh+Gvtl11mtzloXt5wofFK'\
'x4F3iBLrQn9h2je2a8yep5EssLyQyLgqE5bvqby6ijwVghVrY7BBZbTGCotbh6dq'\
'To2IbvMe7iw7jNjxh6MguQaQRPgfm7WQj7vUSV3ZgH/VmCymYfKTFF7vK8mjvQKn'\
'EEXqqw=='

def make_hello():
    hello = ClientHelloMessage.create(TLSRecord.TLS1_0,
                                      '01234567890123456789012345678901',
                                      [TLS_RSA_WITH_RC4_128_MD5,
                                       TLS_RSA_WITH_RC4_128_SHA,
                                       TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                       TLS_RSA_WITH_AES_128_CBC_SHA,
                                       TLS_RSA_WITH_AES_256_CBC_SHA,
                                       TLS_RSA_WITH_AES_128_CBC_SHA256,
                                       TLS_RSA_WITH_AES_256_CBC_SHA256])
    
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=hello.bytes)

    #hexdump(record.bytes)
    return record.bytes


def process_response(sock):

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
                    print('handshake:%s(%x)|' % (message.message_types[message.message_type()], message.server_version()))
                else:
                    print('handshake:%s|' % (message.message_types[message.message_type()]))

                if message.message_type() == HandshakeMessage.ServerHelloDone:
                    got_done = True

                if got_done:
                    continue

        elif record.content_type() == TLSRecord.Alert:
            alert = AlertMessage.from_bytes(record.message())

            if alert.alert_level() == AlertMessage.Fatal:
                print('alert:%s:fatal|' % alert.alert_types[alert.alert_type()])
                break
            else:
                print('alert:%s:warning|' % alert.alert_types[alert.alert_type()])
        else:
            if record.content_type() in record.content_types:
                print('record:%s|' % record.content_types[record.content_type()])
            else:
                print('record:type(%x)|' % record.content_type())

        if got_done:
            break

def sendcert(f):
    print('Sending Client Hello...')
    f.write(make_hello())

    certs = [b64decode(cert_b64)]

    certificate = CertificateMessage.create(certs)
    record = TLSRecord.create(content_type=TLSRecord.Handshake,
                              version=TLSRecord.TLS1_0,
                              message=certificate.bytes)
    f.write(record.bytes)

    process_response(f)
    process_response(f)

    
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

    sendcert(f)
 
if __name__ == '__main__':
    main()


