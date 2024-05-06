"""
Sara Cohen

SMTP Server Script

This script implements a simple SMTP server that communicates with SMTP clients following the SMTP protocol.

Usage:
    1. Run the script to start the SMTP server.
    2. Ensure that the client connects to the correct server IP and port.

The server performs the following steps:
    1. Sends an initial welcome message upon client connection.
    2. Handles EHLO command to initiate communication.
    3. Handles AUTH LOGIN command for user authentication.
    4. Validates and processes the username and password.
    5. Handles MAIL FROM command to specify the sender's email address.
    6. Handles RCPT TO command to specify the recipient's email address.
    7. Initiates the data transfer phase (DATA).
    8. Receives the email content from the client.
    9. Sends a confirmation response after successfully receiving the email content.
    10. Handles QUIT command to close the connection.

Note: Update placeholder values such as IP, SOCKET_TIMEOUT, SERVER_NAME, and user_names according to your use case.

"""

import base64
import socket
from datetime import date
import SMTP_protocol

IP = "127.0.0.1"
SOCKET_TIMEOUT = 1
SERVER_NAME = "test_SMTP_server.com"

user_names = {"shooki": "abcd1234", "barbie": "helloken"}


def create_initial_response():
    """Create the initial server response upon client connection."""
    code = SMTP_protocol.SMTP_SERVICE_READY
    return "{}-{} ESMTP Exim {} -0500 \r\n" \
           "{}-We do not authorize the use of this system to transport unsolicited,\r\n" \
           "{} and/or bulk e-mail.\r\n"\
        .format(code, SERVER_NAME, date.today(), code, code).encode()


def create_EHLO_response(client_message):
    """Create the server response for EHLO command."""
    if not client_message.startswith("EHLO"):
        return SMTP_protocol.COMMAND_SYNTAX_ERROR.encode()
    client_name = client_message.split()[1]
    return "{}-{} Hello {}\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED, SERVER_NAME, client_name).encode()


def create_USER_request(client_message):
    """Create the server response for AUTH LOGIN command (Username)."""
    if not client_message.startswith("AUTH LOGIN"):
        return SMTP_protocol.COMMAND_SYNTAX_ERROR.encode()
    return "{} {}\r\n".format(SMTP_protocol.AUTH_INPUT, base64.b64encode("Username".encode()).decode()).encode()


def create_PASSWORD_request(user):
    """Create the server response for AUTH LOGIN command (Password)."""
    if user.decode() not in user_names:
        return SMTP_protocol.INCORRECT_AUTH.encode()
    return "{} {}\r\n".format(SMTP_protocol.AUTH_INPUT, base64.b64encode("Password".encode()).decode()).encode()


def create_AUTH_SUCCESS_response(user, password):
    """Create the server response for successful authentication."""
    if password.decode() != user_names[user.decode()]:
        return SMTP_protocol.INCORRECT_AUTH.encode()
    return SMTP_protocol.AUTH_SUCCESS.encode()


def create_MAIL_FROM_response(client_message):
    """Create the server response for MAIL FROM command."""
    if not client_message.startswith("MAIL FROM:"):
        return SMTP_protocol.COMMAND_SYNTAX_ERROR.encode()
    # Additional validation and processing for MAIL FROM
    return "{} OK\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED).encode()


def create_RCPT_TO_response(client_message):
    """Create the server response for RCPT TO command."""
    if not client_message.startswith("RCPT TO:"):
        return SMTP_protocol.COMMAND_SYNTAX_ERROR.encode()
    # Additional validation and processing for RCPT TO
    return "{} Accepted\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED).encode()


def create_DATA_response(client_message):
    """Create the server response for DATA command."""
    if not client_message.startswith("DATA"):
        return SMTP_protocol.COMMAND_SYNTAX_ERROR.encode()
    # Additional validation and processing for DATA
    return SMTP_protocol.ENTER_MESSAGE.encode()


def create_REQUESTED_ACTION_COMPLETED_response():
    """Create the server response for successful completion of a command."""
    return "{} OK\r\n".format(SMTP_protocol.REQUESTED_ACTION_COMPLETED).encode()


def create_GOODBYE_response(c_message, client_name):
    """Create the server response for QUIT command."""
    if not c_message.startswith('QUIT'):
        return SMTP_protocol.COMMAND_SYNTAX_ERROR.encode()
    return "{} {} closing connection\r\n".format(SMTP_protocol.GOODBYE, client_name).encode()


def handle_SMTP_client(client_socket):
    """Handle the SMTP communication with a connected client."""
    # 1 send initial message
    s_message = create_initial_response()
    print('server:', s_message.decode())
    client_socket.send(s_message)

    # 2 receive and send EHLO
    c_message = client_socket.recv(1024).decode()
    client_name = c_message.split()[1]
    print('client:', c_message)
    s_message = create_EHLO_response(c_message)
    client_socket.send(s_message)
    print('server:', s_message.decode())
    if not s_message.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error client EHLO")
        return

    # 3 receive and send AUTH Login
    c_message = client_socket.recv(1024).decode()
    print('client:', c_message)
    s_message = create_USER_request(c_message)
    print('server:', s_message.decode())
    client_socket.send(s_message)
    if not s_message.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print("Error client AUTH LOGIN")
        return

    # 4 receive  USER message
    c_message = client_socket.recv(1024).decode()
    print('client:', c_message)
    user = base64.b64decode(c_message)
    # 5 password
    s_message = create_PASSWORD_request(user)
    print('server:', s_message.decode())
    client_socket.send(s_message)
    if not s_message.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print("Error client Username")
        return

    c_message = client_socket.recv(1024).decode()
    print('client:', c_message)
    password = base64.b64decode(c_message)
    s_message = create_AUTH_SUCCESS_response(user, password)
    client_socket.send(s_message)
    print('server:', s_message.decode())
    if not s_message.decode().startswith(SMTP_protocol.AUTH_SUCCESS):
        print("Error client password")
        return

    # 6 mail from
    c_message = client_socket.recv(1024).decode()
    print('client:', c_message)
    s_message = create_MAIL_FROM_response(c_message)
    client_socket.send(s_message)
    print('server:', s_message.decode())
    if not s_message.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error client MAIL FROM")
        return

    # 7 rcpt to
    c_message = client_socket.recv(1024)
    print('client:', c_message.decode())
    s_message = create_RCPT_TO_response(c_message.decode())
    print('server:', s_message.decode())
    client_socket.send(s_message)
    if not s_message.decode().startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error client RCPT TO")
        return

    # 8 DATA
    c_message = client_socket.recv(1024).decode()
    print('client:', c_message)
    s_message = create_DATA_response(c_message)
    print('server:', s_message.decode())
    client_socket.send(s_message)
    if not s_message.decode().startswith(SMTP_protocol.ENTER_MESSAGE):
        print("Error client DATA")
        return

    # 9 email content
    # The server should keep receiving data, until the sign of end email is received
    email_content = ""
    while True:
        data = client_socket.recv(1024).decode()
        if not data:
            break
        email_content += data
        if SMTP_protocol.EMAIL_END in email_content:
            break

    print("Received email content:")
    print(email_content)
    s_message = create_REQUESTED_ACTION_COMPLETED_response()
    print('server:', s_message.decode())
    client_socket.send(s_message)

    # 10 quit
    c_message = client_socket.recv(1024).decode()
    print('client:', c_message)
    s_message = create_GOODBYE_response(c_message, client_name)
    print('server:', s_message.decode())
    client_socket.send(s_message)
    if not s_message.decode().startswith(SMTP_protocol.GOODBYE):
        print("Error client QUIT")
        return
    client_socket.close()


def main():
    """Main function to run the SMTP server."""
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, SMTP_protocol.PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(SMTP_protocol.PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_SMTP_client(client_socket)
        print("Connection closed")


if __name__ == "__main__":
    # Call the main handler function
    main()
