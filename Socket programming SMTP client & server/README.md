
# Socket Programming SMTP Client & Server

This exercise focuses on implementing an SMTP client and server using only the `socket` and `base64` libraries. The client-server system reads user input, sends it to the server, receives the server response, and transmits it back to the client, following the SMTP protocol.

## Solution Overview

### Client Side:
- The `SMTP_client.py` script establishes a connection with the server using SMTP messages such as "EHLO" message.
- It base64 encodes messages required in the protocol.
- Constructs an email with the required fields and the string indicating email end.

### Server Side:
- The `SMTP_server.py` script responds to client connection establishment with proper SMTP responses.
- Includes a known combination of username and password for client authentication.
- Utilizes SMTP error messages for incorrect client actions or authentication failure.
- Prints all incoming and outgoing messages.
- Supports handling a single client at a time.

### Protocol Constants
- All protocol constants, including error codes and port, are defined in `SMTP_protocol.py` for clarity.

## Requirements
- Python 3.x

## Running the Server
1. Open a terminal.
2. Navigate to the directory containing the server script.
3. Run the following command to start the server:
   ```
   python STMP_server.py
   ```

## Running the Client
1. Open another terminal.
2. Navigate to the directory containing the client script.
3. Run the following command to start the client:
   ```
   python STMP_client.py
   ```

## Notes:
- Ensure that the server is running before starting the client.
- Update placeholder values such as server address, port, usernames, and passwords according to your configuration.
