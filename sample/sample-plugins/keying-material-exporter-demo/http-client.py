#!/usr/bin/python
import sys
import os
import httplib

f = '/tmp/openvpn_sso_user'
with open (f, "r") as myfile:
	session_key = myfile.read().replace('\n', '')

conn = httplib.HTTPConnection("10.8.0.1:8080")
conn.request("GET", "/" + session_key)
r1 = conn.getresponse()

if r1.status == 200:
	body = r1.read().rstrip()
	print body
elif r1.status == 404:
	print "Authentication failed"
else:
	print r1.status, r1.reason
