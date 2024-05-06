import socket
import protocol

# Constants
SERVER_ADDRESS = "127.0.0.1"
PORT = protocol.PORT
RSA_PUBLIC_KEY = 1229
RSA_PRIVATE_KEY = 11669


def main():
    try:
        # Connect to the server
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect((SERVER_ADDRESS, PORT))

        # Diffie Hellman Key Exchange
        dh_client_private_key = protocol.diffie_hellman_private_key()
        dh_client_public_key = protocol.diffie_hellman_calc_public_key(dh_client_private_key)
        protocol.send_key(my_socket, dh_client_public_key)
        dh_server_public_key = protocol.rec_key(my_socket)
        shared_secret = protocol.diffie_hellman_calc_shared_secret(dh_server_public_key, dh_client_private_key)

        # RSA Key Exchange
        protocol.send_key(my_socket, RSA_PUBLIC_KEY)
        rsa_other_side = protocol.rec_key(my_socket)

        # Main loop for sending and receiving messages
        while True:
            user_input = input("Enter command\n")
            msg = protocol.create_msg_to_send(user_input, shared_secret, RSA_PRIVATE_KEY)
            my_socket.send(msg)

            if user_input == 'EXIT':
                print("You asked to close the connection")
                break

            # Receive and process server's response
            valid_msg, message = protocol.get_msg(my_socket)
            if not valid_msg:
                print("Received an invalid message length")
            elif not protocol.decoding_and_verifying_msg(message, shared_secret, rsa_other_side):
                print("Failed to decode or verify the message")

    except ConnectionRefusedError:
        print("Connection refused. Make sure the server is running.")
    except ConnectionError:
        print("Connection error. The server may have closed the connection.")
    except Exception as e:
        print("An unexpected error occurred:", e)
    finally:
        print("Closing the connection")
        my_socket.close()


if __name__ == "__main__":
    main()
