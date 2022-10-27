#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re

PATTERN_INVALID_CHARACTERS = r"[^a-z0-9\-]"
REGEX_INVALID_CHARACTERS = re.compile(PATTERN_INVALID_CHARACTERS, re.I)

#: Regular expression for matching a valid serial number
PATTERN_VALID_SERIAL = r"^([a-z0-9]|[a-z0-9]+[a-z0-9\-]*[a-z0-9])$"
REGEX_VALID_SERIAL = re.compile(PATTERN_VALID_SERIAL, re.I)


def mangled_serial_number(value, strict=False):
    """
    Mangle input for use as serial number

    Args:
        value (str): input value

    Returns:
        str: mangled

    >>> mangled_serial_number("123")
    '123'
    >>> mangled_serial_number(123)
    '123'
    >>> mangled_serial_number(0)
    '0'
    >>> mangled_serial_number(0.0)
    '00'
    >>> mangled_serial_number(None)
    Traceback (most recent call last):
        ...
    ValueError: None
    >>> mangled_serial_number("")
    Traceback (most recent call last):
        ...
    ValueError: ''
    >>> mangled_serial_number("k-s_n_w-123")
    'k-snw-123'
    >>> mangled_serial_number("-")
    Traceback (most recent call last):
        ...
    ValueError: '-'
    >>> mangled_serial_number("a-")
    Traceback (most recent call last):
        ...
    ValueError: 'a-'
    >>> mangled_serial_number("--")
    Traceback (most recent call last):
        ...
    ValueError: '-'
    >>> mangled_serial_number("-1-1")
    Traceback (most recent call last):
        ...
    ValueError: '-1-1'
    >>> mangled_serial_number("0-0")
    '0-0'
    >>> mangled_serial_number("0--------------0")
    '0-0'
    >>> mangled_serial_number("123-ix")
    '123-ix'
    >>> mangled_serial_number("123:ix")
    '123ix'
    >>> mangled_serial_number("myPmXYZ-123", strict=True)
    'mypmxyz-123'
    >>> mangled_serial_number("mYPmxyZ-12 3", strict=True)
    'mypmxyz-123'
    >>> mangled_serial_number("my PmxyZ-12 3", strict=True)
    'mypmxyz-123'
    >>> mangled_serial_number("m_y P_____________mxyZ-12 3", strict=True)
    'mypmxyz-123'
    >>> mangled_serial_number("myPmxyZ-------------------------12 3", strict=True)
    'mypmxyz-123'
    >>> mangled_serial_number("x-12345/1", strict=True)
    'x-123451'
    >>> mangled_serial_number("x-12345:1", strict=True)
    'x-123451'
    >>> import uuid
    >>> u_value = str(uuid.uuid4())
    >>> mangled_serial_number(u_value, strict=True) == u_value
    True
    """
    if value != 0 and not value:
        raise ValueError(repr(value))

    try:
        mangled = re.sub(REGEX_INVALID_CHARACTERS, "", value)
    except TypeError:
        mangled = re.sub(REGEX_INVALID_CHARACTERS, "", str(value))

    mangled = re.sub("\-+", "-", mangled)

    if not REGEX_VALID_SERIAL.match(mangled):
        raise ValueError(repr(mangled))

    if strict:
        return mangled.lower()

    return mangled


if __name__ == "__main__":
    import doctest
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # logging.basicConfig(loglevel=logging.DEBUG)
    (FAILED, SUCCEEDED) = doctest.testmod()
    print("[doctest] SUCCEEDED/FAILED: {:d}/{:d}".format(SUCCEEDED, FAILED))
