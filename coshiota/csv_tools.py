#!/usr/bin/env python
# -*- coding: utf-8 -*-
def guess_column_count(filelike):
    """
    Try to guess the column count of CSV data in ``filelike``

    Args:
        filelike: CSV data iterator

    Returns:
        int: number of columns
    """
    sample = filelike.read(1024)
    filelike.seek(0)
    try:
        lines = sample.split(b"\n")
    except TypeError:
        lines = sample.split("\n")

    first_line = lines[0]

    try:
        cols = first_line.strip().split(b";")
    except TypeError:
        cols = first_line.strip().split(";")

    return len(cols)
