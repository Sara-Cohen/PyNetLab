
# PyNetLab - Advanced Socket Exercise: Multi-User Chat

PyNetLab's "Advanced Socket Exercise: Multi-User Chat" is part of the Advanced Computer Networks course. This exercise focuses on implementing a multi-user chat system using socket programming in Python.

## Exercise Overview

The exercise involves writing a server and a client that enable chat between multiple users. The server and client files, along with the protocol file, are provided. The client supports various commands, including setting a name, getting names, sending messages, and exiting.

### Supported Commands:

- **NAME <name>**: Set name. Server will reply with an error if the name is already taken.
- **GET_NAMES**: Get all names of connected clients.
- **MSG <NAME> <message>**: Send a message to a client by name.
- **EXIT**: Close the client.

## Solution Files

The solution includes three Python files:

1. **chat_client.py** : Client implementation using the `select` function for non-blocking I/O.
2. **chat_server.py** : Server implementation handling client requests and managing connections.
3. **chat_protocol.py**: Protocol file containing constants, message parsing functions, and name validation logic.

## Installation and Usage

### Requirements

- Python 3.x
- msvcrt module (for Windows)

### Running the Server

1. Open a terminal.
2. Navigate to the directory containing the solution files.
3. Run the following command to start the server:
   ```
   python chat_server.py
   ```
   The server will start listening for client connections.

### Running the Client

1. Open a separate terminal.
2. Navigate to the directory containing the solution files.
3. Run the following command to start the client:
   ```
   python chat_client.py
   ```
4. Enter commands as instructed by the exercise.

## Additional Notes

- Both the server and the client utilize a protocol file with a length field for message receipt.
- The client's implementation utilizes the `select` function for non-blocking I/O and the `msvcrt` module for handling user input.
