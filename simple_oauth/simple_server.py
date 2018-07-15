from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json
import os

class SimpleServer(BaseHTTPRequestHandler):

    auth_response_path = ""

    def do_POST(self):
        parsed_result = urlparse(self.path)
        qs = urlparse(self.path)
        params = parse_qs(qs.query)
        SimpleServer.auth_response_path= params['auth_response_path'][0]
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        qs = urlparse(self.path)
        auth_response = parse_qs(qs.query)
        if 'state' not in auth_response or 'code' not in auth_response:
            # If this isn't the Auth get request, ignore it
            return
        with open(SimpleServer.auth_response_path,'w') as outfile:
            json.dump(auth_response,outfile)

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"""
        <html>
            <body>
                <h1>Thanks! You are authenticated</h1>
                <p>You may now close the window.</p>
            </body>
        </html>
        """)
