#!/usr/bin/env python
# -*- coding: utf-8 -*-
import shlex


def parsed_cmdline():
    data = dict()

    with open("/proc/cmdline", "rt") as src:
        content = src.read().strip()

        for portion in shlex.split(content):
            key, value = portion, True
            if "=" in portion:
                key, value = portion.split("=", 1)
            data[key] = value

    return data
