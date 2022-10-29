#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import ssl
from urllib.parse import urlparse
import logging

import pendulum
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from cryptography.x509 import load_pem_x509_certificate

from coshiota.tools import log_traceback

EXPIRING_SOON_THRESHOLD = pendulum.Duration(days=7)


class InvalidCertificate(ValueError):
    pass


def evaluated_certificate(certificate_obj, source_hint="", u_now=None):
    if u_now is None:
        u_now = pendulum.now(pendulum.UTC)

    dt_not_before = pendulum.instance(certificate_obj.not_valid_before)
    dt_not_after = pendulum.instance(certificate_obj.not_valid_after)
    subject = certificate_obj.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value

    data = dict(
        obj=certificate_obj,
        dt_now=u_now,
        dt_not_before=dt_not_before,
        dt_not_after=dt_not_after,
        delta_left=u_now - dt_not_after,
        subject=subject,
        expired=not dt_not_before < u_now < dt_not_after,
        expiring_soon=u_now + EXPIRING_SOON_THRESHOLD >= dt_not_after,
        source_hint=source_hint,
    )

    return data


class CertificateLoader:
    def __init__(self, uri_or_location, *args, **kwargs):
        self.log = logging.getLogger(__name__)
        self.path = None
        self.certificate_obj = None
        self.passphrase = b""

        if not kwargs.get("tz"):
            self.tz = "Europe/Paris"
        else:
            self.tz = kwargs.get("tz")

        if not kwargs.get("dt_fmt"):
            self.dt_fmt = "YYYY-MM-DD HH:mm:ss Z"
        else:
            self.dt_fmt = kwargs.get("dt_fmt")

        try:
            self.passphrase = kwargs.get("passphrase", "").encode()
        except Exception:
            pass

        try:
            self.p_url = urlparse(uri_or_location)
        except Exception:
            self.p_url = None

        try:
            self.uri = self.p_url.geturl()
        except AttributeError:
            self.uri = None

        try:
            if os.path.exists(uri_or_location):
                self.path = uri_or_location
        except Exception:
            pass

        # self.log.debug(
        #    f"uri_or_location={uri_or_location} => path={self.path} uri={self.uri}"
        # )

        # if self.path:
        #    self.log.debug(f" => PATH={self.path}")
        # else:
        #    self.log.debug(f" => URI={self.uri}")

        try:
            self.certificate_obj = self._load()
        except Exception as exc:
            log_traceback("error loading certificate", exc, self.log)

    def _load(self):
        if self.p_url and self.path is None:
            if self.p_url.scheme == "https":
                try:
                    (hostname, port) = self.p_url.netloc.split(":")
                    port = int(port)
                    assert 1 <= port <= 65535
                except ValueError:
                    hostname = self.p_url.netloc
                    port = 443

                cert_data = ssl.get_server_certificate((hostname, port))
                # self.log.debug(repr(cert_data))
                return load_pem_x509_certificate(cert_data.encode())
        elif self.path is not None:
            with open(self.path, "rb") as src:
                st_cert = src.read()
                cert_obj = None

                if cert_obj is None:
                    try:
                        cert_obj = load_pem_x509_certificate(st_cert)
                    except Exception as exc:
                        self.log.debug(exc)

                if cert_obj is None:
                    try:
                        _, cert_obj, _ = pkcs12.load_key_and_certificates(
                            st_cert, self.passphrase
                        )
                    except Exception as exc:
                        self.log.debug(exc)

                if cert_obj is None:
                    raise InvalidCertificate(self.uri)

                return cert_obj
        else:
            raise InvalidCertificate(self.uri)

    def __str__(self):
        return f"<{self.__class__.__name__} {self.uri}{not self.valid and ' INVALID' or ''}>"

    def __repr__(self):

        if self.valid:
            edict = self.evaluated_certificate
            not_valid_before = (
                edict["dt_not_before"].in_tz(self.tz).format(self.dt_fmt)
            )
            not_valid_after = (
                edict["dt_not_after"].in_tz(self.tz).format(self.dt_fmt)
            )
            expired_indicator = edict["expired"] and " EXPIRED" or ""
            expiring_soon_indicator = (
                edict["expiring_soon"] and " EXPIRING SOON" or ""
            )
            subject = edict["subject"]

            return f"<{self.__class__.__name__} {self.uri} {subject} {not_valid_before} -- {not_valid_after}{expired_indicator}{expiring_soon_indicator}>"

        return f"<{self.__class__.__name__} {self.uri} INVALID>"

    @property
    def valid(self):
        return self.certificate_obj is not None

    @property
    def evaluated_certificate(self):
        if not self.valid:
            raise InvalidCertificate(self.uri)

        return evaluated_certificate(
            self.certificate_obj, source_hint=self.uri
        )
