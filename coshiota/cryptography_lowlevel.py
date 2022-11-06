#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""

.. seealso:

    * https://std.com/~dtd/sign_encrypt/sign_encrypt7.html
    * https://www.comparitech.com/blog/information-security/what-is-fernet/
    * https://pycryptodome.readthedocs.io/en/latest/src/examples.html#encrypt-data-with-rsa
    * https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
    * https://cryptography.io/en/latest/x509/tutorial/#determining-certificate-or-certificate-signing-request-key-type
    * https://cryptography.io/en/latest/x509/reference/#cryptography.x509.Certificate.tbs_certificate_bytes

"""
import struct
from collections import namedtuple
from typing import Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa
from cryptography.fernet import Fernet
import cryptography
import cryptography.exceptions

MAGIC = 262866705
VERSION_TOW_FERNET = 1
VERSION_TOW_NACL = 2
VERSION_DEFAULT = VERSION_TOW_FERNET
SUPPORTED_VERSIONS = {1}

try:
    import nacl.secret
    import nacl.utils

    SUPPORTED_VERSIONS.add(VERSION_TOW_NACL)
except ImportError:
    pass

# magic, version, offset encrypted_session_key, offset symmetric_encrypted,
# offset inner signature, offset outer signature
BLOB_HEADER_FORMAT = f"!lBllll"

BLOB_HEADER_SIZE = struct.calcsize(BLOB_HEADER_FORMAT)

BlobPortions = namedtuple(
    "BlobPortions",
    (
        "encrypted_session_key",
        "symmetric_encrypted",
        "inner_signature_offset",
        "outer_signature",
        "header_data",
    ),
)

BlobHeaderPortions = namedtuple(
    "BlobHeaderPortions",
    (
        "magic",
        "version",
        "o_encrypted_session_key",
        "o_symmetric_encrypted",
        "o_inner_sig",
        "o_outer_sig",
    ),
)


class BlobUnsupportedVersion(ValueError):
    pass


class BlobInvalidSignatureInner(cryptography.exceptions.InvalidSignature):
    pass


class BlobInvalidSignatureOuter(cryptography.exceptions.InvalidSignature):
    pass


def mk_blob(
    encrypted_session_key: bytes,
    symmetric_encrypted: bytes,
    inner_signature_offset: int,
    outer_signature: bytes,
    version: int,
    **kwargs,
) -> bytes:
    encrypted_session_key_offset = BLOB_HEADER_SIZE
    symmetric_encrypted_offset = encrypted_session_key_offset + len(
        encrypted_session_key
    )
    outer_signature_offset = symmetric_encrypted_offset + len(
        symmetric_encrypted
    )

    blob = (
        struct.pack(
            BLOB_HEADER_FORMAT,
            MAGIC,
            version,
            encrypted_session_key_offset,
            symmetric_encrypted_offset,
            inner_signature_offset,
            outer_signature_offset,
        )
        + encrypted_session_key
        + symmetric_encrypted
        + outer_signature
    )

    return blob


def split_blob(blob: bytes) -> BlobPortions:
    blob_length = len(blob)
    header_data = BlobHeaderPortions(
        *struct.unpack(BLOB_HEADER_FORMAT, blob[:BLOB_HEADER_SIZE])
    )
    (
        r_magic,
        r_version,
        o_encrypted_session_key,
        o_symmetric_encrypted,
        o_inner_sig,
        o_outer_sig,
    ) = header_data

    assert r_magic == MAGIC
    assert r_version in SUPPORTED_VERSIONS
    assert BLOB_HEADER_SIZE == o_encrypted_session_key
    assert (
        o_encrypted_session_key
        < o_symmetric_encrypted
        < o_outer_sig
        < blob_length
    )

    return BlobPortions(
        blob[o_encrypted_session_key:o_symmetric_encrypted],
        blob[o_symmetric_encrypted:o_outer_sig],
        o_inner_sig,
        blob[o_outer_sig:],
        header_data,
    )


def mk_verifiable_blob(
    message: bytes,
    sender_key: rsa.RSAPrivateKey,
    recipient_key: rsa.RSAPublicKey,
    **kwargs,
) -> bytes:
    version = kwargs.get("version", VERSION_DEFAULT)
    assert version in SUPPORTED_VERSIONS

    if version == VERSION_TOW_FERNET:
        session_key = Fernet.generate_key()
        f = Fernet(session_key)
    elif version == VERSION_TOW_NACL:
        session_key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        box = nacl.secret.SecretBox(session_key)
    else:
        raise BlobUnsupportedVersion(version)

    inner_signature = sign_by(message + session_key, sender_key)
    inner_signature_offset = len(message)

    if version == VERSION_TOW_FERNET:
        symmetric_encrypted = f.encrypt(message + inner_signature)
    elif version == VERSION_TOW_NACL:
        symmetric_encrypted = box.encrypt(message + inner_signature)

    encrypted_session_key = encrypt_for(session_key, recipient_key)
    outer_signature = sign_by(
        encrypted_session_key + symmetric_encrypted, sender_key
    )

    return mk_blob(
        encrypted_session_key,
        symmetric_encrypted,
        inner_signature_offset,
        outer_signature,
        version=version,
    )


def decrypt_verifiable_blob(
    blob: bytes, sender_key: rsa.RSAPublicKey, recipient_key: rsa.RSAPrivateKey
):
    (
        encrypted_session_key,
        symmetric_encrypted,
        inner_signature_offset,
        outer_signature,
        header_data,
    ) = split_blob(blob)

    session_key = decrypt_for(encrypted_session_key, recipient_key)

    if header_data.version == VERSION_TOW_FERNET:
        f = Fernet(session_key)
        decrypted = f.decrypt(symmetric_encrypted)
    elif header_data.version == VERSION_TOW_NACL:
        box = nacl.secret.SecretBox(session_key)
        decrypted = box.decrypt(symmetric_encrypted)
    else:
        raise BlobUnsupportedVersion(header_data.version)

    message = decrypted[:inner_signature_offset]
    signature = decrypted[inner_signature_offset:]

    try:
        verify_signature_by(message + session_key, signature, sender_key)
    except cryptography.exceptions.InvalidSignature:
        raise BlobInvalidSignatureInner("Inner signature invalid!")

    try:
        verify_signature_by(
            encrypted_session_key + symmetric_encrypted,
            outer_signature,
            sender_key,
        )
    except cryptography.exceptions.InvalidSignature:
        raise BlobInvalidSignatureOuter("Outer signature invalid!")

    return message, session_key, signature


def decrypt_verifiable_blob_simple(
    blob: bytes, sender_key: rsa.RSAPublicKey, recipient_key: rsa.RSAPrivateKey
) -> bytes:
    message, session_key, signature = decrypt_verifiable_blob(
        blob, sender_key, recipient_key
    )

    return message


def encrypt_for(message: bytes, public_key: rsa.RSAPublicKey) -> bytes:
    """
    (RSA) Encryption of value for given key.

    Args:
        message (bytes): value
        public_key (rsa.RSAPublicKey): Recipient's public key

    Raises:
        ValueError: When no suitable public key was provided

    Returns:
        bytes: encrypted value
    """

    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    raise ValueError(public_key)


def decrypt_for(message: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    """
    (RSA) decryption of value using given key.

    Args:
        message (bytes): encrypted value
        private_key (rsa.RSAPrivateKey): Recipient's private key

    Raises:
        ValueError: When no suitable private key was provided

    Returns:
        bytes: decrypted value
    """

    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    raise ValueError(private_key)


def sign_by(
    message: bytes,
    private_key: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey],
) -> bytes:
    """
    Sign given value using private key.

    Args:
        message (bytes): value
        private_key (Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]): private key

    Raises:
        ValueError: When no suitable private key was provided

    Returns:
        bytes: signature
    """

    if isinstance(private_key, rsa.RSAPrivateKey):
        return private_key.sign(
            data=message,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        return private_key.sign(
            data=message,
            signature_algorithm=ec.ECDSA(hashes.SHA256()),
        )
    else:
        raise ValueError(private_key)


def verify_signature_by(
    message: bytes,
    signature: bytes,
    public_key: Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey],
) -> None:
    """
    Verify signature of given value using provided public key

    Args:
        message (bytes): value
        signature (bytes): signature
        public_key (Union[rsa.RSAPublicKey, ec.EllipticCurvePublicKey]): public key

    Raises:
        ValueError: When no suitable public key was provided

    """

    if isinstance(public_key, rsa.RSAPublicKey):
        return public_key.verify(
            signature=signature,
            data=message,
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key.verify(
            signature=signature,
            data=message,
            signature_algorithm=ec.ECDSA(hashes.SHA256()),
        )
    else:
        raise ValueError(public_key)


if __name__ == "__main__":
    import doctest

    (FAILED, SUCCEEDED) = doctest.testmod()
    print(f"[doctest] SUCCEEDED/FAILED: {SUCCEEDED:d}/{FAILED:d}")
