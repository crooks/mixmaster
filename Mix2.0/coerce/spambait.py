#!/usr/bin/python
import rfc822
import sys
import regex

begPGP = regex.compile('^-----BEGIN PGP MESSAGE-----')
endPGP = regex.compile(' ^-----END PGP MESSAGE-----')

m = rfc822.Message(sys.stdin)

lines = 0
addresses = 0

while 1:
    line = m.fp.readline()
    if not line: break
    if begPGP.search(line) != -1:
	while 1:
	    line = m.fp.readline()
	    if not line: break
	    if endPGP.search(line) != -1: break
    else:
	lines = lines + 1
	if '@' in line:
	    name,addr = rfc822.parseaddr(line)
	    if addr: addresses = addresses + 1

if lines == 0: sys.exit(0)
sys.exit( (2.0**addresses-lines)>0 )
