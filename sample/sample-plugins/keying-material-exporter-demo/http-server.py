#!/usr/bin/python
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import os

class ExampleHTTPRequestHandler(BaseHTTPRequestHandler):

	def do_GET(self):
		session_key = os.path.basename(self.path)
		file = '/tmp/openvpn_sso_' + session_key
		print 'session file: ' + file
		try:
			f = open(file)
			#send code 200 response
			self.send_response(200)
			#send header first
			self.send_header('Content-type','text-html')
			self.end_headers()
			#send file content to client
			user = f.read().rstrip()
			print 'session user: ' + user
			print 'session key:  ' + session_key
			self.wfile.write('<html><body><h1>Greetings ' + user \
					+ '. You are authorized' \
					'</h1>' \
					'</body></html>')
			f.close()
			return
		except IOError:
			self.send_error(404, 'authentication failed')

def run():
	#ip and port of servr
	#by default http server port is 80
	server_address = ('0.0.0.0', 8080)
	httpd = HTTPServer(server_address, ExampleHTTPRequestHandler)
	print('http server started')
	httpd.serve_forever()
	print('http server stopped')

if __name__ == '__main__':
	run()
