

# chat_protocol.py
PORT = 5555
MAX_MSG_LENGTH = 1024
# ENCODING = "utf-8"

# Commands
NAME_COMMAND = "NAME"
GET_NAMES_COMMAND = "GET_NAMES"
MSG_COMMAND = "MSG"
EXIT_COMMAND = "EXIT"
HELLO_RESPONSE = "HELLO"


def parse_message(data):
    parts = data.split(' ', 1)
    command = parts[0]
    args = parts[1] if len(parts) > 1 else ""
    return command, args


def check_valid_name(name):
    if len(name.split()) > 1:
        # Ensures that name have a single word
        return False
    if not name.isalpha():
        return False
    if name.isupper() or name.islower():
        return True
    else:
        return False
