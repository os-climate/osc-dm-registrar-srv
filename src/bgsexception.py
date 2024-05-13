# Copyright 2023 Broda Group Software Inc.
#
# Created: 2023-07-06 by eric.broda@brodagrouopsoftware.com

class BgsException(Exception):
    """
    General exception
    """
    def __init__(self, message, original_exception=None):
        super().__init__(message)
        self.original_exception = original_exception

class BgsNotFoundException(BgsException):
    """
    Resource not found exception
    """
    def __init__(self, message, original_exception=None):
        super().__init__(message)
        self.original_exception = original_exception
