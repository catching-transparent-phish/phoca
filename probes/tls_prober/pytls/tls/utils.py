#!/usr/bin/python

import logging

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

def to_hex(s):
    h = ''
    for b in range(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        h += '  %04x: %-48s %s\n' % (b, hxdat, pdat)
    return h

def hexdump(s):
    print(to_hex(s))
 
class LoggedFile(object):
    def __init__(self, file_):
        self._file = file_
        self.logger = logging.getLogger('pytls')

    def read(self, size):
        data = self._file.read(size)
        self.logger.debug('READ: <<<\n'+to_hex(data)+'\n')
        return data

    def write(self, data):
        self.logger.debug('WRITE: >>>\n'+to_hex(data)+'\n')
        return self._file.write(data)

    def __getattr__(self, attr):
         return getattr(self._file, attr)
