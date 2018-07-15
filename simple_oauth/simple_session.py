import json
import os
import webbrowser
import ssl
import requests
import time
from urllib.parse import urlparse
from requests_oauthlib import OAuth2Session
from http.server import HTTPServer
from flask import Flask

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import hashlib
import datetime
import atexit


try:
    import threading
except ImportError:
    import dummy_threading as threading

from .simple_server import SimpleServer

class SimpleSession():

    token_persistance_format = "simple_token_{}.json"
    auth_response_format = "simple_auth_response_{}.json"


    def __init__(self,
        client_secrets_path=None,
        client_id=None,
        client_secret=None,
        redirect_uri=None,
        auth_uri=None,
        token_uri=None,
        token_refresh_uri=None,
        scope=None,
        certificate=None,
        key=None,
        cache=False,
        ):
        # First parse input parameters
        if client_secrets_path is None:
            self.client_id = self.validate(client_id, "client_id")
            self.client_secret = self.validate(client_secret, "client_secret")
            self.redirect_uri = self.validate(redirect_uri, "redirect_uris")
            self.auth_uri = self.validate(auth_uri, "auth_url")
            self.token_uri = self.validate(token_uri,"token_url")
            self.token_refresh_uri = self.validate(token_refresh_uri, "token_refresh_url")
        else:
            with open(client_secrets_path) as file:
                self.client_secrets_path = client_secrets_path
                params = list(json.load(file).values())[0]
                self.client_id = self.validate(params['client_id'], 'client_id')
                self.client_secret = self.validate(params['client_secret'], 'client_secret')
                # the deafault behavior of Google is to list localhost last so that's what we'll use
                self.redirect_uri = self.validate(params['redirect_uris'][-1], 'redirect_uri')
                self.auth_uri = self.validate(params['auth_uri'],'auth_uri')
                self.token_uri = self.validate(params['token_uri'], 'token_uri')
                self.token_refresh_uri = self.validate(params['token_uri'] or self.token_uri, 'token_refresh_uri')

        self.scope = self.validate(scope,"scope")
        self.cache = self.validate(cache, "cache option")
        self.auto_refresh_kwargs = {
            'client_id': self.client_id,
            'client_secret' : self.client_secret
        }
        self.token_path = os.path.join(os.path.dirname(__file__),SimpleSession.token_persistance_format.format(self._get_file_name_from_arguments()))
        self.auth_response_path = os.path.join(os.path.dirname(__file__),SimpleSession.auth_response_format.format(self._get_file_name_from_arguments()))
        self.simple_certificate_path = certificate or os.path.join(os.path.dirname(__file__),'simple_certificate.pem')
        self.simple_key_path = key or os.path.join(os.path.dirname(__file__),'simple_key.pem')
        self.simple_key = None
        self.internal_session = requests.Session()
        self.cert_pair= (self.simple_certificate_path,self.simple_key_path)

        #Finish validating input parameters

        # Try loading token from persistant storage
        self._try_load_token()

        if(self.token is None):
            # 1. Create session to for getting authorization url
            self._create_authorization_session()

            # 2. Create local https server for managing redirect from token provider
            self._create_redirect_handler()

            # 3. Try loading key and certificate. If not found, then generate defaults
            self._load_ssl_credentials()

            # 4. Open the authorization url and set up the server to handle the authorization reponse
            self._get_authorization_code()

            # 5. Load the auth response from the server from the file system.
            # Saving/loading from file system is the only way I've found to
            # communicate between the custom SimpleServer and the SimpleSession
            # because the HTTPServer instantiates a new SimpleServer for every request
            self._load_authorization_code()

            # 6. Get the token
            self._load_token_from_authorization()

            # 7. Create a session with automatic token refereshing
            self._create_token_renewing_session()

        self._handle_caching()
        self._handle_persistent_storage()

    def _create_authorization_session(self):
        self.oauth2Session = OAuth2Session(self.client_id, redirect_uri=self.redirect_uri,scope=self.scope)
        self.authorization_url, self.state = self.oauth2Session.authorization_url(
            self.auth_uri,
            access_type="offline", prompt="select_account"
        )

    def _create_redirect_handler(self):
        parse_result = urlparse(self.redirect_uri)
        self.server_address = (parse_result.hostname, parse_result.port)
        self.httpd = HTTPServer(self.server_address, SimpleServer)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); 

    def _load_ssl_credentials(self):
        if not os.path.isfile(self.simple_key_path):
            self.generate_key()
        if not os.path.isfile(self.simple_certificate_path):
            self.generate_certificate()

        self.context.load_cert_chain(self.simple_certificate_path, self.simple_key_path)
        self.httpd.socket = self.context.wrap_socket(self.httpd.socket,server_side=True)

    def _get_authorization_code(self):
        self.server_thread = threading.Thread(target=self.httpd.serve_forever)
        self.server_thread.start()
        server_success = False
        while not server_success:
            try:
                self.internal_session.post(
                    'https://{}:{}'.format(self.server_address[0],self.server_address[1]),
                    params={
                        'auth_response_path': self.auth_response_path
                    },
                    cert=self.cert_pair
                )
                server_success = True
            except Exception as e:
                # Could not post the auth response path to the server
                # Try again in 5 seconds
                time.sleep(5)

        webbrowser.open(self.authorization_url)

    def _load_authorization_code(self):
        load_success = False
        while not load_success:
            try:
                self.auth_response = json.load(open(self.auth_response_path))
                load_success = True
            except Exception as e:
                # Could not load the auth response.
                # Wait for writing to file to finish
                time.sleep(5)
        self.httpd.shutdown()
        self.server_thread.join()

    def _load_token_from_authorization(self):
        self.token = self.oauth2Session.fetch_token(
            self.token_uri,
            code=self.auth_response['code'][0],
            client_secret=self.client_secret
        )

    def _create_token_renewing_session(self):
        self.oauth2Session = OAuth2Session(
            client_id=self.client_id,
            token=self.token,
            auto_refresh_url=self.token_refresh_uri,
            auto_refresh_kwargs=self.auto_refresh_kwargs,
            token_updater=self._token_updater
        )

    def _token_updater(self,token):
        self.token = token

    def _persist_token(self):
        with open(self.token_path,'w') as outfile:
            json.dump(self.token,outfile, indent=4)

    def _try_load_token(self):
        try:
            self.token = json.load(open(os.path.abspath(self.token_path)))
            self._create_token_renewing_session()
        except:
            self.token = None

    def _get_file_name_from_arguments(self):
        # 1. Construct a hash of all the parameters
        file_name = ",".join( str(item) for item in [
            self.client_id,
            self.client_secret,
            self.redirect_uri,
            self.auth_uri,
            self.token_uri,
            self.token_refresh_uri
        ])
        file_hash = hashlib.sha256()
        file_hash.update(file_name.encode('utf-8'))

        return file_hash.hexdigest()

    def validate(self, param, name):
        if param is None:
            raise ValueError("Please specify either a client_secrets_path or a " + name)
        return param

    def generate_certificate(self):
        if self.simple_key is None and os.path.isfile(self.simple_key_path):
            self.simple_key = serialization.load_pem_private_key(open(self.simple_key_path,'rb').read(),password=None,backend=default_backend())
        subject = issuer = x509.Name([
             x509.NameAttribute(NameOID.COMMON_NAME, u"simple-oauth"),
        ])
        cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.simple_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Our certificate will be valid for 1 year
                datetime.datetime.utcnow() + datetime.timedelta(weeks=52)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            # Sign our certificate with our private key
            ).sign(self.simple_key, hashes.SHA256(), default_backend())
            # Write our certificate out to disk.
        with open(self.simple_certificate_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    def generate_key(self):
        self.simple_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Write our key to disk for safe keeping
        with open(self.simple_key_path, "wb") as f:
             f.write(self.simple_key.private_bytes(
                 encoding=serialization.Encoding.PEM,
                 format=serialization.PrivateFormat.TraditionalOpenSSL,
                 encryption_algorithm=serialization.NoEncryption(),
             ))

    def get_session(self):
        return self.oauth2Session

    def delete_token(self):
        os.remove(self.token_path)

    def delete_key(self):
        os.remove(self.simple_key_path)

    def delete_certificate(self):
        os.remove(self.simple_certificate_path)

    def _delete_auth_response(self):
        os.remove(self.auth_response_path)

    def nuke(self):
        self.delete_token()
        self.delete_key()
        self.delete_certificate()
        self._delete_auth_response()

    def _handle_caching(self):
        if type(self.cache) is "str" and self.cache.lower() is "dict":
            from cachecontrol import CacheControl
            self.oauth2Session = CacheControl(self.oauth2Session)

    def _handle_persistent_storage(self):
        atexit.register(self._persist_token)
