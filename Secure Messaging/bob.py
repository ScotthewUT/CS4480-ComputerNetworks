# Scott Crowley (u1178178)
# CS4480 - PA 3: Secure Messaging ("Bob")
# 22 April 2020

import argparse, json, os, socket, subprocess, sys

# Constants
BUFFER_SIZE = 4096
MSG_HDR_SIZE = 8
DEFAULT_PORT = 4480
BOB_PRIVATE_KEY  = "bob_priv_key.pem"
BOB_PUBLIC_KEY   = "bob_pub_key.pem"
ALICE_PUBLIC_KEY = "alice_pub_key.pem"
CA_PRIVATE_KEY   = "CA_priv_key.pem"
CA_PUBLIC_KEY    = "CA_pub_key.pem"
SIGNED_HASH_BIN  = "signed_hash.bin"
SIGNED_HASH_TXT  = "signed_hash.txt"
COMBINE_MSG_TXT  = "combine_msg.txt"
ENCRYPT_MSG_BIN  = "encrypt_msg.bin"
ENCRYPT_MSG_TXT  = "encrypt_msg.txt"
ENCRYPT_KEY_BIN  = "encrypt_key.bin"
ENCRYPT_KEY_TXT  = "encrypt_key.txt"

# Global variable
verbose = False

def main():
    global verbose
    # Command line argument handling.
    parser = argparse.ArgumentParser(description = "Bob's secure messaging app. Run this before alice.py!")
    parser.add_argument('-p', '--port', type = int, default = DEFAULT_PORT, metavar = '', help = "Bob's port number")
    parser.add_argument('-v', '--verbose', action = 'store_true', help = "Displays process details in console")
    args = parser.parse_args()
    port = args.port
    verbose = args.verbose
    del parser
    del args

    # Package up Bob's public key to send once a request is received.
    pub_key_msg = PreparePublicKey()

    try:
       # Create a socket, bind it to a port and start listening.
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       sock.bind(('', port))
       sock.listen(5)
    except socket.error, (value, error_msg):
       # Error handling for socket conneciton.
       if sock:
          sock.close()
       print "Socket error: ", error_msg
       sys.exit(1)

    # Handshake with Alice.
    print "\nListening for Alice at ", socket.gethostname(), ":", port, "...\n"
    aliceSock, aliceAddr = sock.accept()
    print "Received a connection from: ", aliceAddr, "\n"

    # Receive request from Alice.
    req = ReceiveMessage(aliceSock)
    print "Alice sent:\n", req

    # Send Alice Bob's public key package.
    ReplyToAlice(aliceSock, pub_key_msg)
    if verbose:
        print "\n~~~ Bob's Public Key (Complete Package) ~~~\n", pub_key_msg

    # Wait for Alice's secure message.
    print "\nListening for Alice at ", socket.gethostname(), ":", port, "...\n"
    aliceSock, aliceAddr = sock.accept()
    print "Received a connection from: ", aliceAddr, "\n"

    # Receive the message from Alice.
    package = ReceiveMessage(aliceSock)
    if verbose:
        print "\n~~~ Alice's Secure Message (Complete Package) ~~~\n", package

    # Convert the JSON message to a dictionary.
    msg_dict = json.loads(package)

    # Write the encrypted session key to file.
    file = open(ENCRYPT_KEY_TXT, "w")
    file.write(msg_dict["key"])
    file.close()
    if verbose:
        print "\n~~~ Encrypted Session Key ~~~\n", msg_dict["key"]

    # OpenSSL - Decode the session key from base-64 back to binary then decrypt it with Bob's private key.
    subprocess.call(["openssl", "base64", "-d", "-in", ENCRYPT_KEY_TXT, "-out", ENCRYPT_KEY_BIN])
    subprocess.call(["openssl", "rsautl", "-decrypt", "-inkey", BOB_PRIVATE_KEY, "-in", ENCRYPT_KEY_BIN, "-out", "session_key.txt"])

    # Get the session key, salt, vector from file.
    file = open("session_key.txt", "r")
    session_key_lines = file.read().splitlines()
    file.close()
    salt = session_key_lines[0].split('=')[1]
    key  = session_key_lines[1].split('=')[1]
    iv   = session_key_lines[2].split('=')[1]
    if verbose:
        print "\n~~~ Session Key ~~~\n", key

    # Write the encrypted message to file.
    file = open(ENCRYPT_MSG_TXT, "w")
    file.write(msg_dict["message"])
    file.close()
    if verbose:
        print "\n~~~ Combined & Encrypted Message ~~~\n", msg_dict["message"]

    # OpenSSL - Decode the message from base-64 back to binary then decrypt it with the session key.
    subprocess.call(["openssl", "base64", "-d", "-in", ENCRYPT_MSG_TXT, "-out", ENCRYPT_MSG_BIN])
    subprocess.call(["openssl", "enc", "-des3", "-d", "-in", ENCRYPT_MSG_BIN, "-out", COMBINE_MSG_TXT, "-S", salt, "-K", key, "-iv", iv])
    
    # Read in the combined message that was just decrypted.
    file = open(COMBINE_MSG_TXT, "r")
    package = file.read()
    file.close()
    if verbose:
        print "\n~~~ Combined Message ~~~\n", package

    # Convert the JSON message to a dictionary.
    msg_dict = json.loads(package)

    # Write Alice's message to file.
    file = open("ALICE_MESSAGE.txt", "w")
    file.write(msg_dict["message"])
    file.close()

    # Write hashed message to file.
    file = open(SIGNED_HASH_TXT, "w")
    file.write(msg_dict["hash"])
    file.close()
    if verbose:
        print "\n~~~ Signature for Alice's Message ~~~\n", msg_dict["hash"]

    # OpenSSL - Decode hashed message from base-64 back to binary then verify it with Alice's public key.
    subprocess.call(["openssl", "base64", "-d", "-in", SIGNED_HASH_TXT, "-out", SIGNED_HASH_BIN])
    os.system("openssl sha1 -verify alice_pub_key.pem -signature signed_hash.bin ALICE_MESSAGE.txt > verify.txt")

    # Read in the verification result.
    file = open("verify.txt", "r")
    result = file.read()
    file.close()
    if verbose:
        print "\n~~~ Alice's Signature Verification Result ~~~\n", result

    # Confirm verification result
    if "OK" in result:
        print "Alice sent:\n", msg_dict["message"]
    else:
        print "Warning: Received a message that did not verify as Alice."

    # Close the listening socket and exit.
    if sock:
        sock.close()
    sys.exit(0)


# This method method converts Bob's public key to a JSON string containing the key
# and a signed hash of the key.
#
# Return:   The JSON string with members "key" and "hash".
def PreparePublicKey():

    # OpenSSL - Hash Bob's public key and sign it with the CA private key then encode in base-64.
    subprocess.call(["openssl", "sha1", "-sign", CA_PRIVATE_KEY, "-out", SIGNED_HASH_BIN, BOB_PUBLIC_KEY])
    subprocess.call(["openssl", "base64", "-e", "-in", SIGNED_HASH_BIN, "-out", SIGNED_HASH_TXT])

    # Read in Bob's public key and put it in a dictionary.
    file = open(BOB_PUBLIC_KEY, "r")
    key_dict = {
        "key": file.read()
    }
    file.close()

    # Read in the encoded, signed hash file and add it to the dictionary.
    file = open(SIGNED_HASH_TXT, "r")
    key_dict["hash"] = file.read()
    file.close()

    if verbose:
        # Print Bob's key and its signature to console.
        print "\n~~~ Bob's Public Key ~~~\n", key_dict["key"]
        print "\n~~~ Signature for Bob's Public Key ~~~\n", key_dict["hash"]

    # Dump the dictionary to JSON and return the string.
    return json.dumps(key_dict)


# This method sends a response message to Alice.
#
# Param:    sock - An active socket connection to Alice.
#           message - The message to send Alice. Its size will be prepended.
def ReplyToAlice(sock, message):

    # Add the message size to the front.
    tcp_msg = PrependMessageSize(message)

    try:
       # Send Alice the package.
       sock.send(tcp_msg)
    except socket.error, (value, error_msg):
       # Error handling for socket connection.
       if sock:
          sock.close()
       print "Socket error: ", error_msg
       sys.exit(1)

    return


# This method prepends a message with an 8-btye string of its size.
#
# Param:    message - A string to prepend with its size.
# Return:   A new string with its original size prepended.
def PrependMessageSize(message):
    
    msg_size = len(message)

    if msg_size > 99999999:
        # Messages larger than the header can represent will break send & receive.
        print "Error: Message is too large."
        sys.exit(1)

    msg_size_str = str(msg_size)
    msg_size_str = msg_size_str.zfill(MSG_HDR_SIZE)
    return msg_size_str + message


# This method receives a message from Alice. The message is expected to be preceded
# with the a short header representing the message size.
#
# Param:    An active socket connection to receive Alice's message.
# Return:   The full received message (minus the header).
def ReceiveMessage(sock):

    # Receive all or part of the message.
    buffer = sock.recv(BUFFER_SIZE)
    # Need to receive at least the message header to determine size.
    while len(buffer) < MSG_HDR_SIZE:
        next = sock.recv(BUFFER_SIZE)
        if next == "":
            # Empty string signals lost connection.
            print "Lost connection to Alice before receiving full message.\n"
            sock.close()
            sys.exit(1)
        # Concatenate the message buffer.
        buffer = "".join([buffer, next])

    # Remove header from buffer.
    msg_size_str = buffer[0:MSG_HDR_SIZE]
    buffer = buffer[(MSG_HDR_SIZE):len(buffer)]
    # Get size of intended message.
    msg_size = int(msg_size_str)

    # Keep receiving until full message has be received.
    while len(buffer) < msg_size:
        next = sock.recv(BUFFER_SIZE)
        if next == "":
            # Empty string signals lost connection.
            print "Lost connection to Alice before receiving full message.\n"
            sock.close()
            sys.exit(1)
        # Concatenate the message buffer.
        buffer = "".join([buffer, next])

    # Return the full message.
    return buffer


if __name__ == '__main__':
    main()