# Scott Crowley (u1178178)
# CS4480 - PA 1: HTTP Web Proxy
# 15 February 2020

# Skeleton code provided by "Computer Networking: A Top-Down Approach" (Kurose & Ross)

import argparse, hashlib, os, re, socket, sys, thread, time, urlparse

# Constants
BACKLOG = 5
BUFFER_SIZE = 4096
DEFAULT_PORT = 80
PROXY_PORT = 2100
TIMEOUT = 120




def main():

    # Package dictionary
    package = {
        "message": "",
        "hash": "",
        "encrypted", "",
        "session": ""
    }

    # Command line argument handling.
    # Usage: "python HTTPproxy.py -k <api_key>"
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-k", "--key", help="API key provided by VirusTotal.")
    args = argParser.parse_args()
    if args.key:
        apiKey = args.key
    del argParser
    del args
    
    try:
       # Create a server socket, bind it to a port and start listening.
       servSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       servSock.bind(('', PROXY_PORT))
       servSock.listen(BACKLOG)
    except socket.error, (value, message):
       # Error handling for socket conneciton.
       if servSock:
          servSock.close()
       print "Proxy socket error: ", message
       sys.exit(1)

    while 1:
      # Handshake with client and start a new thread.
      print "Ready to serve...\n"
      clientSock, clientAddr = servSock.accept()
      print "Received a connection from: ", clientAddr, "\n"
      thread.start_new_thread(ProcessRequest, (clientSock, clientAddr))

    servSock.close()
    sys.exit(0)


# This method processes client HTTP requests and is called as a new thread to
# support multiple clients. HTTP 1.0 and GET method supported.
# Param: clientSock - the TCP client socket
#        clientAddr - the client address
def ProcessRequest(clientSock, clientAddr):
    # Client must send a request before TIMEOUT.
    clientSock.settimeout(TIMEOUT)
    try:
        # Receive request message from client.
        buffer = clientSock.recv(BUFFER_SIZE)
    except socket.timeout:
        if clientSock:
            clientSock.close()
        return

    # Keep receiving until end of header detected or timeout.
    start = int(time.time())
    while not "\r\n\r\n" in buffer:
        time.sleep(0.2)
        try:
            next = clientSock.recv(BUFFER_SIZE)
        except socket.timeout:
            # If no more data is received, timeout the socket.
            InvalidRequest(clientSock, 408)
            return
        if next == "":
            # Empty string signals lost connection.
            print "Lost connection to client.\n"
            clientSock.close()
            return
        # Concatenate the message buffer.
        buffer = "".join([buffer, next])
        if time.time() > start + TIMEOUT:
            # If loop runs too long, timeout the socket.
            InvalidRequest(clientSock, 408)
            return

    # Decompose message on line boundaries.
    request = buffer.splitlines(True)
    requestLine = request[0].split()

    # Malformed request handling:
    if len(requestLine) != 3:
        InvalidRequest(clientSock, 400)
        return
    method = requestLine[0]
    if method != "GET":
        # Only GET method supported.
        if (method == "HEAD" or method == "POST" or method == "PUT" or method == "DELETE"
            or method == "CONNECT" or method == "OPTIONS" or method == "TRACE" or method == "PATCH"):
            InvalidRequest(clientSock, 501)
            return
        else:
            InvalidRequest(clientSock, 400)
            return
    version = requestLine[2].split("/", 1)
    if len(version) != 2:
        InvalidRequest(clientSock, 400)
        return
    if version[0] != "HTTP" or version[1] != "1.0":
        # Only HTTP/1.0 supported.
        InvalidRequest(clientSock, 501)
        return
    url = requestLine[1]
    if url.lower().startswith("https://"):
        # URL should begin with "http://".
        InvalidRequest(clientSock, 501)
        return
    if not url.lower().startswith("http://"):
        InvalidRequest(clientSock, 400)
        return
    if len(url) > 2048:
        # Cap URL size at 2048 char.
        InvalidRequest(clientSock, 414)
        return
    i = 1
    headerNameRegEx = re.compile("[a-zA-Z\-]+\Z")
    # Cursory check of header format:
    while i < len(request) - 1:
        header = request[i].split(":", 1)
        if len(header) < 2 or header[1] == "\r\n":
            # No ':' found or value empty.
            InvalidRequest(clientSock, 400)
            return
        if not headerNameRegEx.match(header[0]):
            # Header name doesn't match "Header-Name:" format.
            InvalidRequest(clientSock, 400)
            return
        if header[0].lower() == "connection":
            # Replace any Connection header to assure its value is "close".
            request[i] = "Connection: close\r\n"
        if header[0].lower() == "host":
            # Remove any Host header lines.
            del request[i]
        i += 1
    if len(request) - 1 > request.index("\r\n"):
        # Client included a body with the GET request or sent another request too soon.
        InvalidRequest(clientSock, 400)
        return

    # Parse the URL:
    parsedURL = urlparse.urlparse(url)
    host = parsedURL.hostname
    path = parsedURL.path
    port = DEFAULT_PORT
    if parsedURL.port is not None:
        port = parsedURL.port
    # Replace request line with relative URL form.
    if path is None:
        requestLine == "GET / HTTP/1.0\r\n"
    else:
        requestLine = "".join(["GET ", path, " HTTP/1.0\r\n"])
    request[0] = requestLine
    # Insert host name as header.
    hostHeader = "".join(["Host: ", host, ":", str(port), "\r\n"])
    request.insert(1, hostHeader)
    # Reconstruct request for server.
    requestMessage = "".join(request)

    # TODO: Remove after debugging...
    print "Request message from", clientAddr, ":"
    print requestMessage

    # Send request on to server.
    response = SendRequest(host, port, requestMessage)

    if response == "500" or response == "504":
        # The target server didn't connect properly.
        InvalidRequest(clientSock, int(response))
        sys.exit(1)
    # Process the server's response message.
    ProcessResponse(clientSock, response)
    return


# This method forwards the client's request on to the target server and returns
# the server's response to ProcessRequest.
# Param: host - target server's host name
#        port - target server's port (default: 80)
#        request - valid HTTP/1.0 GET request
# Ret:   HTTP response message or an error code
def SendRequest(host, port, request):
    try:
        # Initialize socket with target server.
        targetSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        targetSock.settimeout(TIMEOUT)
        targetSock.connect((host, port))
        # Forward client's request.
        targetSock.send(request)
    except socket.timeout:
        # If timed out trying to connect, return 504 error.
        if targetSock:
            targetSock.close()
        return "504"
    except socket.error, (value, message):
        # Any other I/O error, return 500 error.
        if targetSock:
            targetSock.close()
        print "Target server socket error: ", message
        return "500"

    # Keep receiving until empty string or timeout.
    start = int(time.time())
    buffer = ""
    while 1:
        try:
            data = targetSock.recv(BUFFER_SIZE)
        except socket.timeout:
            # If no more data is received, timeout the socket.
            return "504"
        if len(data) > 0:
            # Concatenate the message buffer.
            buffer = "".join([buffer, data])
        else:
            # Empty string signals end of response & socket closed.
            break
        if time.time() > start + TIMEOUT:
            # If loop runs too long, timeout the socket.
            targetSock.close()
            return "504"

    if targetSock:
        # If not already closed, close the socket.
        targetSock.close()
    return buffer


# This method processes the server's response and checks requested file against
# VirusTotal for possible malware.
# Param: clientSock - the TCP client socket
#        response   - a valid HTTP response message
def ProcessResponse(clientSock, response):
    # Decompose response on line boundaries.
    responseList = response.splitlines(True)
    statusLine = responseList[0].split()
    # If response message wasn't a 200 OK, let the client know.
    if statusLine[1] != "200":
        ForwardResponse(clientSock, response)
        return

    # TODO: Figure out how to save response body to file.
    # TODO: Calculate MD5 hash from file.
    # TODO: Request report from VirusTotal with MD5 resource.
    # TODO: Parse VirusTotal response.
    # TODO: If malware detected, replace file with Content Blocked html.
    # TODO: Forward response to client.
    # TODO: Delete file.

    ForwardResponse(clientSock, response)
    return


# Simple helper method forwards the target server's response to the client.
# Param: clientSock - the TCP client socket
#        response   - a valid HTTP response message
def ForwardResponse(clientSock, response):
    try:
        # Forward the server response to the client.
        clientSock.send(response)
    except socket.error, (value, message):
       if clientSock:
          clientSock.close()
       print "Client socket error: ", message
       sys.exit(1)
    if clientSock:
        clientSock.close()
    return


# Helper method that responds to clients with error statuses and closes the connection.
# Param: socket - the TCP client socket
#        error  - HTTP status code
def InvalidRequest(socket, error):
    print "Invalid HTTP/1.0 GET Request!\n"
    if error == 400:
        socket.send("HTTP/1.0 400 Bad Request\r\nConnection: close\r\n\r\n")
    elif error == 501:
        socket.send("HTTP/1.0 501 Not Implemented\r\nConnection: close\r\n\r\n")
    elif error == 500:
        socket.send("HTTP/1.0 500 Internal Server Error\r\nConnection: close\r\n\r\n")
    elif error == 504:
        socket.send("HTTP/1.0 504 Gateway Timeout\r\nConnection: close\r\n\r\n")
    elif error == 408:
        socket.send("HTTP/1.0 408 Request Timeout\r\nConnection: close\r\n\r\n")
    elif error == 414:
        socket.send("HTTP/1.0 414 URI Too Long\r\nConnection: close\r\n\r\n")
    socket.close()


if __name__ == '__main__':
    main()