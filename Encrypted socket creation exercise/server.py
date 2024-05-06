import socket
import protocol

# Constants
RSA_PUBLIC_KEY = 2731
RSA_PRIVATE_KEY = 7171


def create_server_response(cmd):
    """Create a response based on the client's command."""
    if not cmd:
        return "\nServer response:\nYou sent an empty message!\nSend again, I'm really curious what you wanted to tell me"
    return f"\nServer response:\nI repeat after you ^_~ {cmd}"


def main():
    try:
        # Set up server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(("0.0.0.0", protocol.PORT))
        server_socket.listen()
        print("Server is up and running")

        # Accept client connection
        (client_socket, client_address) = server_socket.accept()
        print("Client connected")

        # Diffie Hellman Key Exchange
        dh_server_private_key = protocol.diffie_hellman_private_key()
        dh_server_public_key = protocol.diffie_hellman_calc_public_key(dh_server_private_key)
        client_dh_public = protocol.rec_key(client_socket)
        protocol.send_key(client_socket, dh_server_public_key)
        shared_secret = protocol.diffie_hellman_calc_shared_secret(client_dh_public, dh_server_private_key)

        # RSA Key Exchange
        rsa_other_side = protocol.rec_key(client_socket)
        protocol.send_key(client_socket, RSA_PUBLIC_KEY)

        # Main loop for receiving and sending messages
        while True:
            # Receive client's message
            valid_msg, message = protocol.get_msg(client_socket)
            if not valid_msg:
                print("Received an invalid message length")
                continue

            # Decode and verify the message
            try:
                decrypted_message = protocol.decoding_and_verifying_msg(message, shared_secret, rsa_other_side)
            except Exception as e:
                print("Error occurred during message decoding:", e)
                break

            # Check if client wants to close the connection
            if decrypted_message == "EXIT":
                break

            # Create server response
            response = create_server_response(decrypted_message)
            msg = protocol.create_msg_to_send(response, shared_secret, RSA_PRIVATE_KEY)
            client_socket.send(msg)

    except ConnectionError:
        print("Connection error. The client may have closed the connection.")
    except Exception as e:
        print("An unexpected error occurred:", e)
    finally:
        print("Closing connection")
        client_socket.close()
        server_socket.close()


if __name__ == "__main__":
    main()
