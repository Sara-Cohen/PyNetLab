## Encrypted Socket Creation Exercise

This exercise focuses on implementing the four mechanisms required to create an encrypted socket:

1. **Symmetric Encryption**: Based on a key known only to both parties, using symmetric XOR encryption.
2. **Shared Encryption Key Determination**: Using the Diffie-Hellman algorithm to determine a common encryption key.
3. **Hash Function**: A custom hash function to convert the entire encrypted message into an 11-bit number.
4. **Signature (MAC) Using a Public Key**: Implementing the RSA algorithm for message authentication code (MAC) generation and verification.

### Requirements
- Python 3.x
- No external libraries are required beyond the standard Python libraries.

### Solution Overview

#### Client (`client.py`)
- Establishes a connection with the server and performs key exchange using Diffie-Hellman and RSA algorithms.
- Encrypts outgoing messages using symmetric XOR encryption and signs them using RSA.
- Receives and decrypts messages from the server, verifying their authenticity.

#### Server (`server.py`)
- Listens for incoming connections and performs key exchange with the client.
- Decrypts incoming messages from the client, verifies their authenticity, and generates appropriate responses.
- Utilizes both symmetric encryption and RSA signature for secure communication.

#### Protocol Module (`protocol.py`)
- Contains functions for symmetric encryption/decryption, Diffie-Hellman key exchange, hash calculation, and RSA signature generation/verification.
- Implements message formatting and parsing functions for communication between client and server.

### Installation
No additional installations are required beyond Python itself.

### Running the Server
1. Open a terminal.
2. Navigate to the directory containing `server.py`.
3. Run the following command:
   ```
   python server.py
   ```

### Running the Client
1. Open another terminal.
2. Navigate to the directory containing `client.py`.
3. Run the following command:
   ```
   python client.py
   ```

### Communication Protocol
- During connection establishment, Diffie-Hellman and RSA public keys are exchanged.
- All messages sent between client and server are encrypted using symmetric encryption and include a signature for authentication.

### Note
- Ensure that the server is running before starting the client.
- Adjust server address and port if necessary in `client.py` and `server.py`.
