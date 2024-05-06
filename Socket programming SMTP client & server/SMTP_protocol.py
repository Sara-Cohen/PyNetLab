
PORT = 25
SMTP_SERVICE_READY = "220"
REQUESTED_ACTION_COMPLETED = "250"
COMMAND_SYNTAX_ERROR = "500 Syntax error, command unrecognized\r\n"
AUTH_INPUT = "334"
AUTH_SUCCESS = "235 Authentication succeeded\r\n"
INCORRECT_AUTH = "535 Authentication credentials invalid\r\n"
ENTER_MESSAGE = "354 Enter message, ending with '.' on a line by itself\r\n"
EMAIL_END = "\r\n.\r\n"  # Find which combination of chars indicates email end
GOODBYE = "221"
