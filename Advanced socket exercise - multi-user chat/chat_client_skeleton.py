# chat_client.py
# Sara Cohen

import msvcrt
import socket

import select

import chat_protocol

# NAME <name> will set name. Server will reply error if duplicate
# GET_NAMES will get all names
# MSG <NAME> <message> will send message to client name
# EXIT will close client

my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", chat_protocol.PORT))
print("Pls enter commands\n")
c_msg = ""
while c_msg != "EXIT":

    read_list, wait_list, xlist = select.select([my_socket], [], [], 0.1)
    if read_list:
        s_msg = my_socket.recv(chat_protocol.MAX_MSG_LENGTH).decode()
        if s_msg == " ":
            break
        print(f'Server sent: {s_msg}')
    if msvcrt.kbhit():
        char = msvcrt.getch().decode()
        if char == '\r':  # Enter key pressed
            c_msg += char
            my_socket.send(c_msg.encode())
            print('\r')
            c_msg = ""
        else:
            c_msg += char
            print(char, end='', flush=True)  # Print character immediately to the screen

my_socket.close()
