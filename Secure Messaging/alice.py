# Scott Crowley (u1178178)
# CS4480 - PA 3: Secure Messaging ("Alice")
# 22 April 2020

import argparse, json, os, socket, subprocess, sys

# Constants
BUFFER_SIZE  = 4096
MSG_HDR_SIZE = 8
DEFAULT_PORT = 4480
DEFAULT_MSG  = "message.txt"
ALICE_PRIVATE_KEY = "alice_priv_key.pem"
BOB_PUBLIC_KEY    = "bob_pub_key.pem"
BOB_HASH_KEY_TXT  = "bob_hash_key.txt"
BOB_HASH_KEY_BIN  = "bob_hash_key.bin"
SIGNED_HASH_BIN   = "signed_hash.bin"
SIGNED_HASH_TXT   = "signed_hash.txt"
COMBINE_MSG_TXT   = "combine_msg.txt"
ENCRYPT_MSG_BIN   = "encrypt_msg.bin"
ENCRYPT_MSG_TXT   = "encrypt_msg.txt"
ENCRYPT_KEY_BIN   = "encrypt_key.bin"
ENCRYPT_KEY_TXT   = "encrypt_key.txt"

def main():
    # Command line argument handling.
    parser = argparse.ArgumentParser(description = "Alice's secure messaging app. Run bob.py before this!")
    parser.add_argument('-H', '--host', required = True, help = "Bob's host name or IP address")
    parser.add_argument('-p', '--port', type = int, default = DEFAULT_PORT, metavar = '', help = "Bob's port number")
    parser.add_argument('-f', '--file', default = DEFAULT_MSG, help = "File name/path for Alice's message")
    parser.add_argument('-v', '--verbose', action = 'store_true', help = "Displays process details in console")
    args = parser.parse_args()
    host = args.host
    port = args.port
    msg_file = args.file
    verbose = args.verbose
    del parser
    del args

    # Request Bob's public key then receive it.
    sock = MessageBob("Hi Bob! What's your public key?", host, port)
    package = ReceiveMessage(sock)
    if verbose:
        print "\n~~~ Bob's Public Key (Complete Package) ~~~\n", package

    # Close the socket.
    if sock:
        sock.close()

    # Convert the JSON message to a dictionary.
    key_dict = json.loads(package)

    # Write Bob's public key to file.
    file = open(BOB_PUBLIC_KEY, "w")
    file.write(key_dict["key"])
    file.close()

    # Write the hashed key to file.
    file = open(BOB_HASH_KEY_TXT, "w")
    file.write(key_dict["hash"])
    file.close()
    if verbose:
        print "\n~~~ Signature for Bob's Public Key ~~~\n", key_dict["hash"]
        print "\n~~~ Bob's Public Key ~~~\n", key_dict["key"]

    # OpenSSL - Decode Bob's public key from base-64 back to binary then verify it with the CA key.
    subprocess.call(["openssl", "base64", "-d", "-in", BOB_HASH_KEY_TXT, "-out", BOB_HASH_KEY_BIN])
    os.system("openssl sha1 -verify CA_pub_key.pem -signature bob_hash_key.bin bob_pub_key.pem > verify.txt")

    # Read in the verification result.
    file = open("verify.txt", "r")
    result = file.read()
    file.close()
    if verbose:
        print "\n~~~ Bob's Signature Verification Result ~~~\n", result

    # Confirm verification result
    if not "OK" in result:
        print "Warning: Received a key that did not verify as Bob.  Exiting..."
        sys.exit(1)

    # Read in Alice's message file and put it in a dictionary.
    file = open(msg_file, "r")
    msg_dict = {
        "message": file.read()
    }
    file.close()

    # OpenSSL - Hash the message and sign it with Alice's private key then encode in base-64.
    subprocess.call(["openssl", "sha1", "-sign", ALICE_PRIVATE_KEY, "-out", SIGNED_HASH_BIN, msg_file])
    subprocess.call(["openssl", "base64", "-e", "-in", SIGNED_HASH_BIN, "-out", SIGNED_HASH_TXT])

    # Read in the encoded, signed hash file and add it to the dictionary.
    file = open(SIGNED_HASH_TXT, "r")
    msg_dict["hash"] = file.read()
    file.close()
    if verbose:
        print "\n~~~ Alice's Message for Bob ~~~\n", msg_dict["message"]
        print "\n~~~ Signature for Alice's Message ~~~\n", msg_dict["hash"]

    # Dump the dictionary to JSON and write it to file.
    combined_message = json.dumps(msg_dict)
    file = open(COMBINE_MSG_TXT, "w")
    file.write(combined_message)
    file.close
    msg_dict.pop("hash")
    if verbose:
        print "\n~~~ Combined Message ~~~\n", combined_message

    # OpenSSL - Generate a session key.
    os.system("openssl enc -P -des3 -pass pass:MessageInABottle > session_key.txt")

    # Get the session key, salt, vector from file.
    file = open("session_key.txt", "r")
    session_key_lines = file.read().splitlines()
    file.close()
    salt = session_key_lines[0].split('=')[1]
    key  = session_key_lines[1].split('=')[1]
    iv   = session_key_lines[2].split('=')[1]
    
    # OpenSSL - Use the session key to encrypt the combined message then encode in base-64.
    subprocess.call(["openssl", "enc", "-des3", "-in", COMBINE_MSG_TXT, "-out", ENCRYPT_MSG_BIN, "-S", salt, "-K", key, "-iv", iv])
    subprocess.call(["openssl", "base64", "-e", "-in", ENCRYPT_MSG_BIN, "-out", ENCRYPT_MSG_TXT])

    # Read in the encrypted message and add it to the dictionary.
    file = open(ENCRYPT_MSG_TXT, "r")
    msg_dict["message"] = file.read()
    file.close()
    if verbose:
        print "\n~~~ Combined & Encrypted Message ~~~\n", msg_dict["message"]
        print "\n~~~ Session Key ~~~\n", key

    # OpenSSL - Encrypt the session key using Bob's public key then encode in base-64.
    subprocess.call(["openssl", "rsautl", "-encrypt", "-pubin", "-inkey", BOB_PUBLIC_KEY, "-in", "session_key.txt", "-out", ENCRYPT_KEY_BIN])
    subprocess.call(["openssl", "base64", "-e", "-in", ENCRYPT_KEY_BIN, "-out", ENCRYPT_KEY_TXT])

    # Read in the encrypted session key and add it to the dictionary.
    file = open(ENCRYPT_KEY_TXT, "r")
    msg_dict["key"] = file.read()
    file.close()
    if verbose:
        print "\n~~~ Encrypted Session Key ~~~\n", msg_dict["key"]

    # Dump the dictionary to JSON and send this package to Bob.
    package = json.dumps(msg_dict)
    sock = MessageBob(package, host, port)
    if verbose:
        print "\n~~~ Alice's Secure Message (Complete Package) ~~~\n", package

    # Close the socket and exit.
    if sock:
        sock.close()
    sys.exit(0)


# This method creates a socket, connects to Bob, and sends a given message.
#
# Param:    message - The message to send Bob. Its size will be prepended.
#           host - Bob's host name or IP address
#           port - Bob's port number 
# Return:   The socket opened for this connection.
def MessageBob(message, host, port):

    # Add the message size to the front.
    tcp_msg = PrependMessageSize(message)

    try:
       # Create a socket for Alice to use.
       sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
       # Connect to Bob and send the package.
       sock.connect((host, port))
       sock.send(tcp_msg)
    except socket.error, (value, error_msg):
       # Error handling for socket connection.
       if sock:
          sock.close()
       print "Socket error: ", error_msg
       sys.exit(1)

    return sock


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


# This method receives a message from Bob. The message is expected to be preceded
# with the a short header representing the message size.
#
# Param:    An active socket connection to receive Bob's message.
# Return:   The full received message (minus the header).
def ReceiveMessage(sock):

    # Receive all or part of the message.
    buffer = sock.recv(BUFFER_SIZE)
    # Need to receive at least the message header to determine size.
    while len(buffer) < MSG_HDR_SIZE:
        next = sock.recv(BUFFER_SIZE)
        if next == "":
            # Empty string signals lost connection.
            print "Lost connection to Bob before receiving full message.\n"
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
            print "Lost connection to Bob before receiving full message.\n"
            sock.close()
            sys.exit(1)
        # Concatenate the message buffer.
        buffer = "".join([buffer, next])

    # Return the full message.
    return buffer


if __name__ == '__main__':
    main()