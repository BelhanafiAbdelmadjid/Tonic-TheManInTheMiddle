from flask import Flask
import socket
import sys

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello, Flask!"

def is_port_in_use(host, port):
    """Check if a port is in use."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False

if __name__ == "__main__":
    host = "0.0.0.0"
    port = 443

    if is_port_in_use(host, port):
        print("XX")
        print(f"Port {port} is already in use. Please use a different port or stop the program using it.")
        sys.exit(1)
    
    # Start Flask app if port is free
    app.run(host=host, port=port)
