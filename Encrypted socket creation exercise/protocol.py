import socket
from random import randint

# Constants
LENGTH_FIELD_SIZE = 6
PORT = 8820
DIFFIE_HELLMAN_P = 19
DIFFIE_HELLMAN_G = 21
RSA_P = 137
RSA_Q = 151


def send_key(my_socket, key):
    """Send a key over the socket."""
    if not isinstance(key, str):
        key = str(key)
    my_socket.send(key.encode())


def rec_key(my_socket):
    """Receive a key from the socket."""
    key = my_socket.recv(16)
    key = int(key)
    return key


def symmetric_encryption(input_data, key):
    """Perform symmetric encryption/decryption."""
    key &= 0xFFFF
    if not isinstance(input_data, bytes):
        input_bytes = input_data.encode()
    else:
        input_bytes = input_data
    encrypted_second_part = b''
    if len(input_bytes) % 2 != 0:
        last_byte = input_bytes[-1:]
        input_bytes = input_bytes[0:-1]
        truncated_key_second_part = key & 0xFF
        encrypted_second_part = bytes([b ^ truncated_key_second_part for b in last_byte])
    encrypted_data = bytes([b ^ key for b in input_bytes])
    encrypted_data = encrypted_data + encrypted_second_part
    return bytes(encrypted_data)


def diffie_hellman_private_key():
    """Choose a 16-bit size private key."""
    return randint(0, 2 ** 16 - 1)


def diffie_hellman_calc_public_key(private_key):
    """Calculate the public key for Diffie-Hellman key exchange."""
    return (DIFFIE_HELLMAN_G ** private_key) % DIFFIE_HELLMAN_P


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """Calculate the shared secret for Diffie-Hellman key exchange."""
    return (other_side_public ** my_private) % DIFFIE_HELLMAN_P


def calc_hash(message):
    """Calculate a hash value from the message."""
    if not isinstance(message, str):
        message = str(message)
    hash_value = 0
    for char in message:
        hash_value += ord(char)
    return hash_value % 20687


def calc_signature(hash, RSA_private_key):
    """Calculate the signature using RSA algorithm."""
    if isinstance(hash, str):
        hash = int(hash)
    signature = (hash ** RSA_private_key) % (RSA_P * RSA_Q)
    return hex(signature)


def create_msg(data):
    """Create a message to send over the socket."""
    if not isinstance(data, bytes):
        data = str(data).encode()
    length = len(data)
    hex_length = hex(length)
    hex_string = hex_length[:2] + hex_length[2:].zfill(4)
    hex_string = hex_string.encode()
    return bytes(hex_string + data)


def get_msg(my_socket):
    """Receive and parse a message from the socket."""
    length_field = my_socket.recv(LENGTH_FIELD_SIZE)
    try:
        length = int(length_field, 16)
    except ValueError:
        return False, "Error: Invalid length field"
    cipher_text = my_socket.recv(length)
    mac = my_socket.recv(LENGTH_FIELD_SIZE)
    try:
        mac = int(mac.decode(), 16)
    except ValueError:
        return False, "Error: Invalid MAC field"
    message = [cipher_text, mac]
    return True, message


def create_msg_to_send(content_of_the_message, shared_key, RSA_PRIVATE_KEY):
    """Create a message to send including encryption and signature."""
    hash_message = calc_hash(content_of_the_message)
    signature_message = calc_signature(hash_message, RSA_PRIVATE_KEY)
    encrypt_message = symmetric_encryption(content_of_the_message, shared_key)
    msg = bytes(create_msg(encrypt_message) + signature_message.encode())
    print(f"The encrypted message you send:\n{msg.decode()}")
    return msg


def decoding_and_verifying_msg(message, shared_key, rsa_other_side):
    """Decrypt and verify the received message."""
    decrypt_message = (symmetric_encryption(message[0], shared_key)).decode()
    hash_rec_message = calc_hash(decrypt_message)
    received_hash_signature = calc_signature(message[1], rsa_other_side)
    received_hash_signature = int(received_hash_signature, 16)
    if hash_rec_message == received_hash_signature:
        print("Signature verification succeeded!")
        print(f"The message received is :{decrypt_message}")
        return decrypt_message
    else:
        return False
#
# def test_protocol():
#     """Test the basic functionality of the protocol."""
#     # Dummy data for testing
#     shared_key = diffie_hellman_private_key()
#     rsa_private_key = 1234
#     rsa_other_side = 5678
#     message = "Hello, world!"
#     # Dummy socket for testing
#     dummy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     # Test sending and receiving keys
#     send_key(dummy_socket, shared_key)
#     received_key = rec_key(dummy_socket)
#     assert received_key == shared_key
#     # Test creating and receiving messages
#     encrypted_msg = create_msg_to_send(message, shared_key, rsa_private_key)
#     dummy_socket.send(encrypted_msg)
#     valid_msg, received_msg = get_msg(dummy_socket)
#     assert valid_msg == True
#     assert received_msg[0] == symmetric_encryption(message, shared_key)
#     # Test decoding and verifying message
#     decrypted_msg = decoding_and_verifying_msg(received_msg, shared_key, rsa_other_side)
#     assert decrypted_msg == message
#     print("Protocol tests passed successfully!")
#
# if __name__ == "__main__":
#     test_protocol()
