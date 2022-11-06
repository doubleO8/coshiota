#!/usr/bin/env python
# -*- coding: utf-8 -*-
from typing import Union

import pendulum
import orjson
from cryptography.x509.base import Certificate
from cryptography.hazmat.primitives.asymmetric.types import PRIVATE_KEY_TYPES

from coshiota.cryptography_lowlevel import VERSION_DEFAULT
from coshiota.cryptography_lowlevel import mk_verifiable_blob
from coshiota.cryptography_lowlevel import decrypt_verifiable_blob_simple


class TrustyPayloadMessage:
    def __init__(
        self,
        payload=None,
        sender_private: Union[PRIVATE_KEY_TYPES, None] = None,
        sender_public: Union[Certificate, None] = None,
        recipient_private: Union[PRIVATE_KEY_TYPES, None] = None,
        recipient_public: Union[Certificate, None] = None,
    ):
        if not payload:
            payload = dict()
        self.dt = pendulum.now()
        self.payload = payload
        self.sender_private = sender_private
        self.sender_public = sender_public
        self.recipient_private = recipient_private
        self.recipient_public = recipient_public

    def __str__(self):
        kind = "VIRGIN"
        a = ""
        b = ""

        if self.sender_private:
            kind = "TO:"

            try:
                a = f"{self.sender_public.subject} "
            except Exception:
                pass

            try:
                b = f" {self.recipient_public.subject}"
            except Exception:
                pass
        elif self.recipient_private:
            kind = "FROM:"

            try:
                a = f"{self.recipient_public.subject} "
            except Exception:
                pass

            try:
                b = f" {self.sender_public.subject}"
            except Exception:
                pass

        return f"<{self.__class__.__name__} {a}{kind}{b} {self.payload}>"

    def get_bytes(
        self,
        **kwargs,
    ) -> bytes:
        assert self.sender_private is not None
        assert self.recipient_public is not None

        version = kwargs.get("version", VERSION_DEFAULT)
        self.dt = pendulum.now()
        self.payload["dt"] = self.dt.timestamp()
        message = orjson.dumps(self.payload)

        return mk_verifiable_blob(
            message,
            self.sender_private,
            self.recipient_public.public_key(),
            version=version,
        )

    def parse_bytes(self, blob: bytes):
        assert self.sender_public is not None
        assert self.recipient_private is not None

        message = decrypt_verifiable_blob_simple(
            blob,
            self.sender_public.public_key(),
            self.recipient_private,
        )
        self.payload = orjson.loads(message)
        self.dt = pendulum.from_timestamp(self.payload["dt"])

    @classmethod
    def create(
        cls,
        payload: dict,
        sender_private: PRIVATE_KEY_TYPES,
        recipient_public: Certificate,
        sender_public: Union[Certificate, None] = None,
    ):
        return TrustyPayloadMessage(
            payload,
            sender_private=sender_private,
            sender_public=sender_public,
            recipient_public=recipient_public,
        )

    @classmethod
    def load(
        cls,
        blob: bytes,
        sender_public: Certificate,
        recipient_private: PRIVATE_KEY_TYPES,
        recipient_public: Union[Certificate, None] = None,
    ):
        obj = TrustyPayloadMessage(
            sender_public=sender_public,
            recipient_private=recipient_private,
            recipient_public=recipient_public,
        )
        obj.parse_bytes(blob)

        return obj
