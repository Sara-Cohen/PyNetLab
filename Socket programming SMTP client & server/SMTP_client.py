"""
Sara Cohen

SMTP Client Script

This script establishes a connection to an SMTP server, performs a series of actions following the SMTP protocol, and sends a sample email.

Usage:
    1. Ensure the SMTP server is running.
    2. Update the SMTP server address and port in the 'my_socket.connect' method.
    3. Run the script.

The script performs the following steps:
    1. Connects to the SMTP server.
    2. Sends EHLO message to initiate communication.
    3. Performs authentication using AUTH LOGIN mechanism.
    4. Specifies the sender's email address (MAIL FROM).
    5. Specifies the recipient's email address (RCPT TO).
    6. Initiates the data transfer phase (DATA).
    7. Sends the email content.
    8. Quits the session (QUIT).

Note: Replace placeholder values such as CLIENT_NAME, user, password, sender@example.com, and recipient@example.com
      with actual values according to your use case.

"""

import base64
import socket
import SMTP_protocol

CLIENT_NAME = "client.com"

# Add the minimum required fields to the email
EMAIL_TEXT = \
    "From: sender@example.com\r\n" \
    "To: recipient@example.com\r\n" \
    "Subject: Funniest Joke Ever\r\n" \
    "\r\n" \
    "Why don't scientists trust atoms?\r\n" \
    "Because they make up everything!"


def create_EHLO():
    """Create EHLO message."""
    return "EHLO {}\r\n".format(CLIENT_NAME).encode()


def create_AUTH_LOGIN():
    """Create AUTH LOGIN message."""
    return "AUTH LOGIN\r\n".encode()


def create_USER(user):
    """Create USER message with base64-encoded username."""
    return base64.b64encode(user.encode()) + b'\r\n'


def create_PASSWORD(password):
    """Create PASSWORD message with base64-encoded password."""
    return base64.b64encode(password.encode()) + b'\r\n'


def create_MAIL_FROM():
    """Create MAIL FROM message."""
    return "MAIL FROM: <sender@example.com>\r\n".encode()


def create_RCPT_TO():
    """Create RCPT TO message."""
    return "RCPT TO: <recipient@example.com>\r\n".encode()


def create_DATA():
    """Create DATA message."""
    return "DATA\r\n".encode()


def create_EMAIL_CONTENT():
    """Create email content with the minimum required fields."""
    line = SMTP_protocol.EMAIL_END
    return "{}{}\r\n".format(EMAIL_TEXT, line).encode()


def create_QUIT():
    """Create QUIT message."""
    return "QUIT\r\n".encode()


def main():
    # Connect to server
    my_socket = socket.socket()
    my_socket.connect(("127.0.0.1", SMTP_protocol.PORT))
    s_response = my_socket.recv(1024).decode()

    # 1 server welcome message
    # Check that the welcome message is according to the protocol
    if not s_response.startswith(SMTP_protocol.SMTP_SERVICE_READY):
        print("Error connecting")
        my_socket.close()
        return

    # 2 EHLO message
    message = create_EHLO()
    my_socket.send(message)
    s_response = my_socket.recv(1024).decode()
    print(s_response)
    if not s_response.startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error connecting")
        my_socket.close()
        return

    # 3 AUTH LOGIN
    message = create_AUTH_LOGIN()
    my_socket.send(message)

    # 4 User
    s_response = my_socket.recv(1024).decode()

    if not s_response.startswith(SMTP_protocol.AUTH_INPUT):
        print("Error connecting")
        my_socket.close()
        return
    user = "barbie"
    message = create_USER(user)
    my_socket.send(message)

    # 5 password
    s_response = my_socket.recv(1024)

    if not s_response.decode().startswith(SMTP_protocol.AUTH_INPUT):
        print("Error user name")
        my_socket.close()
        return
    password = "helloken"
    message = create_PASSWORD(password)
    my_socket.send(message)

    # 6 mail from
    s_response = my_socket.recv(1024).decode()
    if not s_response.startswith(SMTP_protocol.AUTH_SUCCESS):
        print("Error password")
        my_socket.close()
        return
    message = create_MAIL_FROM()
    my_socket.send(message)

    # 7 rcpt to
    s_response = my_socket.recv(1024).decode()
    if not s_response.startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error in MAIL FROM")
        my_socket.close()
        return
    message = create_RCPT_TO()
    my_socket.send(message)
    s_response = my_socket.recv(1024).decode()
    if not s_response.startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error in RCPT_TO")
        my_socket.close()
        return

    # 8 data
    message = create_DATA()
    my_socket.send(message)
    s_response = my_socket.recv(1024).decode()
    if not s_response.startswith(SMTP_protocol.ENTER_MESSAGE):
        print("Error in DATA")
        my_socket.close()
        return

    # 9 email content
    email_message = create_EMAIL_CONTENT()
    my_socket.send(email_message)

    # 10 quit
    s_response = my_socket.recv(1024).decode()
    if not s_response.startswith(SMTP_protocol.REQUESTED_ACTION_COMPLETED):
        print("Error in email content")
        my_socket.close()
        return
    message = create_QUIT()
    my_socket.send(message)
    s_response = my_socket.recv(1024).decode()
    if not s_response.startswith(SMTP_protocol.GOODBYE):
        print("Error in QUIT")
        my_socket.close()
        return

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
