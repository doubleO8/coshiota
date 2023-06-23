#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import logging
import traceback

import pendulum
import orjson


def log_traceback(message, exception, uselog=None):
    """
    Use *uselog* Logger to log a Traceback of exception *exception*.

    Args:
        message(str): message to be logged before trace log items
        exception(Exception): exception to be logged
        uselog(logging.Logger, optional): logger instance override

    """
    if uselog is None:
        uselog = logging.getLogger(__name__)
    e_type, e_value, e_traceback = sys.exc_info()

    uselog.warning(message)
    uselog.error(exception)

    for line in traceback.format_exception(e_type, e_value, e_traceback):
        for part in line.strip().split("\n"):
            if part != "":
                uselog.warning(part)


def dump_json(data, uselog=None, level=logging.INFO):
    """
    Log ``data`` in JSON format

    Args:
        data: data
        uselog(logging.Logger, optional): logger instance override
        level: logging level

    """
    if uselog is None:
        uselog = logging.getLogger(__name__)

    for line in orjson.dumps(
        data,
        option=orjson.OPT_INDENT_2 | orjson.OPT_APPEND_NEWLINE,
    ).split(b"\n"):
        uselog.log(level, line.decode("utf-8"))

def dump_json_to_stdout(data):
    """
    Dump ``data`` in JSON format to STDOUT

    Args:
        data: data

    """
    for line in orjson.dumps(
        data,
        option=orjson.OPT_INDENT_2 | orjson.OPT_APPEND_NEWLINE,
    ).split(b"\n"):
        print(line.decode("utf-8"))


def load_json(path):
    """
    Load JSON encoded file and return its contents.

    Args:
        path(str): path

    Returns:
        object: parsed content

    """
    with open(path, "rb") as src:
        content = orjson.loads(src.read())

    return content


def persist_json(data, path, indent=None, sort_keys=False):
    """
    Persist ``data`` in JSON format to ``path``.

    Args:
        data: data
        path: file path
        indent (int, optional): indent
        sort_keys (bool, optional): do sort keys

    """
    option = 0

    if indent:
        option |= orjson.OPT_INDENT_2

    if sort_keys:
        option |= orjson.OPT_SORT_KEYS

    with open(path, "wb") as tgt:
        tgt.write(orjson.dumps(data, option=option))


def vcrap(env_name=None):
    data = dict()

    try:
        data = orjson.loads(os.environ["VCAP_APPLICATION"])
    except Exception:
        pass

    space_name = data.get("space_name", "")

    if "prod" in space_name:
        env_name = "prod"
    elif "qa" in space_name:
        env_name = "qa"
    elif "dev" in space_name:
        env_name = "dev"

    if env_name:
        data["env_name"] = env_name

    return data


def period_object(period):
    """
    Convert *period* to  a ``pendulum.Period`` object if needed and possible.

    Args:
        period: input data

    Returns:
        period (pendulum.Period): period object
    """
    if isinstance(period, dict):
        try:
            try:
                return pendulum.Period(
                    pendulum.parse(period["begin"]),
                    pendulum.parse(period["end"]),
                )
            except KeyError:
                return pendulum.Period(
                    pendulum.parse(period["start"]),  # allowing also 'start'
                    pendulum.parse(period["end"]),
                )
        except KeyError:
            raise ValueError(
                "Cannot make a period object out of {!r}".format(period)
            )
    elif isinstance(period, pendulum.Period):
        return period

    raise ValueError("Cannot make a period object out of {!r}".format(period))


def period_json(period):
    """
    Convert a ``pendulum.Period`` object to a JSON serialisable dict.

    Args:
        period (pendulum.Period): period object

    Returns:
        dict: period specification
    """
    if isinstance(period, dict):
        period = period_object(period)

    return {
        "total_seconds": period.total_seconds(),
        "begin": period.start.to_iso8601_string(),
        "end": period.end.to_iso8601_string(),
    }
