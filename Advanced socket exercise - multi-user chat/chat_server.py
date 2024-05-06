# chat_server.py
# Sara Cohen

import socket

import select

import chat_protocol

# Constants
SERVER_PORT = 5555
SERVER_IP = "0.0.0.0"


def find_key_by_value(dictionary, target_value):
    # Function to find a key in a dictionary based on the target value
    for key, value in dictionary.items():
        if value == target_value:
            return key
    return None


def handle_name_command(current_socket, args, clients_names):
    # Handles the NAME command, allowing clients to set their names
    name = args.strip()

    if not chat_protocol.check_valid_name(name):
        reply = "The name is invalid!"
    elif current_socket in clients_names.values() and name not in clients_names.keys():
        # If the current socket is associated with a name, replace the name
        key = find_key_by_value(clients_names, current_socket)
        clients_names[name] = clients_names.pop(key)
        reply = f"{key} replace name to {name}"
    elif name not in clients_names.keys():
        # If the name is not in use, set the name
        clients_names[name] = current_socket
        reply = f"{chat_protocol.HELLO_RESPONSE} {name}"
    else:
        # If the name already exists, provide an error message
        reply = "Error: Name already exists"
    return reply, current_socket


def handle_get_name_command(current_socket, clients_names):
    # Handles the GET_NAMES command, providing a list of all connected client names
    names = " ".join(clients_names.keys())
    return names, current_socket


def handle_message_command(data, clients_names, current_socket):
    # Handles the MSG command, facilitating communication between clients
    dest, message = chat_protocol.parse_message(data)

    if len(message.split()) > 1:
        # Ensures that messages have a single word
        reply = "The message must have one word!"
        dest_socket = current_socket
    elif dest in clients_names.keys():
        # If the recipient exists, send the message
        key = find_key_by_value(clients_names, current_socket)
        dest_socket = clients_names[dest]
        reply = f"{key} sent {message}"
    else:
        # If the recipient does not exist, provide an error message
        dest_socket = current_socket
        reply = "Recipient not found!"
    return reply, dest_socket


def handle_exit_command(current_socket, clients_names):
    # Handles the EXIT command, disconnecting a client
    sender_name = find_key_by_value(clients_names, current_socket)
    clients_names.pop(sender_name)
    current_socket.close()
    return "", None


def handle_incorrect_command(current_socket):
    # Handles cases where an unknown command is received
    reply = 'Incorrect command, try again!'
    return reply, current_socket


def handle_client_request(current_socket, data, clients_names):
    # Processes client requests based on the received command and arguments
    command, args = chat_protocol.parse_message(data)
    if command.startswith(chat_protocol.NAME_COMMAND):
        reply, dest_socket = handle_name_command(current_socket, args, clients_names)
    elif command.startswith(chat_protocol.GET_NAMES_COMMAND):
        reply, dest_socket = handle_get_name_command(current_socket, clients_names)
    elif command.startswith(chat_protocol.MSG_COMMAND):
        reply, dest_socket = handle_message_command(args, clients_names, current_socket)
    elif command.startswith(chat_protocol.EXIT_COMMAND):
        reply, dest_socket = handle_exit_command(current_socket, clients_names)
    else:
        reply, dest_socket = handle_incorrect_command(current_socket)
    return reply, dest_socket


def print_client_sockets(client_sockets):
    for c in client_sockets:
        print("\t", c.getpeername())


def main():
    print("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()
    print("Listening for clients...")
    client_sockets = []
    messages_to_send = []
    clients_names = {}
    while True:
        read_list = client_sockets + [server_socket]
        ready_to_read, ready_to_write, in_error = select.select(read_list, client_sockets, [])
        for current_socket in ready_to_read:
            if current_socket is server_socket:
                client_socket, client_address = server_socket.accept()
                print("New client joined!\n", client_address)
                client_sockets.append(client_socket)
                print_client_sockets(client_sockets)
            else:
                print("New data from client\n")
                try:
                    # Violent closure treatment
                    data = current_socket.recv(chat_protocol.MAX_MSG_LENGTH).decode()
                except ConnectionError:
                    data = ""
                if data == "":
                    sender_name = find_key_by_value(clients_names, current_socket)
                    if sender_name:
                        clients_names.pop(sender_name)
                    else:
                        sender_name = "Unknown client"
                    print(f"The connection with client {sender_name} has been closed\n")
                    client_sockets.remove(current_socket)
                    current_socket.close()
                else:
                    print(data)
                    (response, dest_socket) = handle_client_request(current_socket, data, clients_names)
                    messages_to_send.append((dest_socket, response))

        # write to everyone (note: only ones which are free to read...)
        for message in messages_to_send:
            current_socket, data = message
            if current_socket in ready_to_write:
                current_socket.send(data.encode())
                messages_to_send.remove(message)


if __name__ == '__main__':
    main()
