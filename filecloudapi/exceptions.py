# Copyright (c) 2024 FileCloud. All Rights Reserved.


class ServerError(Exception):
    """
    Generic Error with FileCloud server (connection)
    """

    def __init__(self, code: str, message: str):
        """
        Initialize the exception with code and message
        """
        super().__init__(message)
        self.code = code
