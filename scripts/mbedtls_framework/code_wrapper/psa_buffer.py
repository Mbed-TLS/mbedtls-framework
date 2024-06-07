import os
from typing import Iterator, List, Optional, Tuple

from mbedtls_framework import build_tree
from mbedtls_framework import c_parsing_helper
from mbedtls_framework import c_wrapper_generator
from mbedtls_framework import typing_util


class BufferParameter:
    """Description of an input or output buffer parameter sequence to a PSA function."""
    #pylint: disable=too-few-public-methods

    def __init__(self, i: int, is_output: bool,
                 buffer_name: str, size_name: str) -> None:
        """Initialize the parameter information.
        i is the index of the function argument that is the pointer to the buffer.
        The size is argument i+1. For a variable-size output, the actual length
        goes in argument i+2.
        buffer_name and size_names are the names of arguments i and i+1.
        This class does not yet help with the output length.
        """
        self.index = i
        self.buffer_name = buffer_name
        self.size_name = size_name
        self.is_output = is_output
