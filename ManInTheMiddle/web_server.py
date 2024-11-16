from flask import Flask,redirect,render_template,flash,request,make_response,jsonify
from flask_cors import CORS
import os
import json, os, signal
class WEBServer:
    
    def __init__(self) -> None:
        '''
            Flask web server
        '''
    def shutdown_server(self):
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()

    def listen(self):
        app = Flask(__name__)
        app.secret_key = 'dqsddqdsdgfrgerefdmkodsjfhdslkj<fhdsqopfhdspofh'
        CORS(app)

        @app.route("/")
        def index():
            return render_template('index.html')
            #return "Hello world"
        
        @app.post("/index")
        def data():
            print(request.data)
            flash(f"Received data: Name - {request.data}")
            response = make_response(jsonify(None), 200)
            return response
        
        @app.route('/force_shutdown', methods=['POST'])
        def force_shutdown():
            # os._exit(0)
            # self.shutdown_server()
            os.kill(os.getpid(), signal.SIGINT)
            return make_response(jsonify(None), 200)

        app.run(host='0.0.0.0',port=443,debug=False, use_reloader=False, ssl_context=('ssl_cert/cert.pem', 'ssl_cert/key.pem')) 
        


if __name__ == "__main__":
    w = WEBServer()
    w.listen()

