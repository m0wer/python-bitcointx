# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

"""Native BIP327 MuSig2 wrappers for libsecp256k1's v0.6.0+ musig module.

These primitives support 32-byte messages and x-only tweaks. See the README's
Taproot and MuSig2 scope section for protocol responsibilities and nonce safety.
"""

import ctypes
import os
import threading
from typing import Any, Sequence, SupportsIndex, Tuple, cast

from bitcointx.core.secp256k1 import (
    SECP256K1_EC_COMPRESSED,
    Secp256k1,
    get_secp256k1,
)


KEYAGG_CACHE_SIZE = 197
SECNONCE_SIZE = 132
PUBNONCE_SIZE = 132
AGGNONCE_SIZE = 132
SESSION_SIZE = 133
PARTIAL_SIG_SIZE = 36


class MuSig2Error(ValueError):
    """Raised when a MuSig2 contribution or session is invalid."""


def _zero_buffer(buffer: Any, size: int) -> None:
    ctypes.memset(buffer, 0, size)


def _require_musig() -> Secp256k1:
    secp256k1 = get_secp256k1()
    if not secp256k1.cap.has_musig:
        raise MuSig2Error(
            "libsecp256k1 MuSig2 support is unavailable; rebuild it with --enable-module-musig"
        )
    return secp256k1


def _require_bytes(value: object, size: int, name: str) -> bytes:
    if not isinstance(value, bytes):
        raise MuSig2Error(f"{name} must be bytes")
    if len(value) != size:
        raise MuSig2Error(f"{name} must be exactly {size} bytes long")
    return value


def _require_bytes_sequence(value: object, name: str) -> Tuple[bytes, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray, str)):
        raise MuSig2Error(f"{name} must be a sequence of bytes")
    if not value:
        raise MuSig2Error(f"{name} must not be empty")
    return tuple(cast(bytes, item) for item in value)


def _validate_scalar(secp256k1: Secp256k1, value: object, name: str) -> bytes:
    scalar = _require_bytes(value, 32, name)
    if secp256k1.lib.secp256k1_ec_seckey_verify(secp256k1.ctx.sign, scalar) != 1:
        raise MuSig2Error(f"{name} is not a valid secp256k1 scalar")
    return scalar


def _parse_pubkey(secp256k1: Secp256k1, value: object, name: str) -> Tuple[bytes, Any]:
    pubkey = _require_bytes(value, 33, name)
    if pubkey[0] not in (2, 3):
        raise MuSig2Error(f"{name} must use compressed serialization")

    parsed = ctypes.create_string_buffer(64)
    if (
        secp256k1.lib.secp256k1_ec_pubkey_parse(secp256k1.ctx.verify, parsed, pubkey, len(pubkey))
        != 1
    ):
        _zero_buffer(parsed, 64)
        raise MuSig2Error(f"{name} is not a valid secp256k1 public key")
    return pubkey, parsed


def _parse_pubnonce(secp256k1: Secp256k1, value: object, name: str) -> Any:
    pubnonce = _require_bytes(value, 66, name)
    parsed = ctypes.create_string_buffer(PUBNONCE_SIZE)
    if secp256k1.lib.secp256k1_musig_pubnonce_parse(secp256k1.ctx.verify, parsed, pubnonce) != 1:
        _zero_buffer(parsed, PUBNONCE_SIZE)
        raise MuSig2Error(f"{name} is not a valid MuSig2 public nonce")
    return parsed


def _parse_aggnonce(secp256k1: Secp256k1, value: object, name: str) -> Any:
    aggnonce = _require_bytes(value, 66, name)
    parsed = ctypes.create_string_buffer(AGGNONCE_SIZE)
    if secp256k1.lib.secp256k1_musig_aggnonce_parse(secp256k1.ctx.verify, parsed, aggnonce) != 1:
        _zero_buffer(parsed, AGGNONCE_SIZE)
        raise MuSig2Error(f"{name} is not a valid MuSig2 aggregate nonce")
    return parsed


def _parse_partial_sig(secp256k1: Secp256k1, value: object, name: str) -> Any:
    partial_sig = _require_bytes(value, 32, name)
    parsed = ctypes.create_string_buffer(PARTIAL_SIG_SIZE)
    if (
        secp256k1.lib.secp256k1_musig_partial_sig_parse(secp256k1.ctx.verify, parsed, partial_sig)
        != 1
    ):
        _zero_buffer(parsed, PARTIAL_SIG_SIZE)
        raise MuSig2Error(f"{name} is not a valid MuSig2 partial signature")
    return parsed


def _serialize_pubnonce(secp256k1: Secp256k1, pubnonce: Any) -> bytes:
    serialized = ctypes.create_string_buffer(66)
    try:
        if (
            secp256k1.lib.secp256k1_musig_pubnonce_serialize(
                secp256k1.ctx.verify, serialized, pubnonce
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 could not serialize the MuSig2 public nonce")
        return serialized.raw
    finally:
        _zero_buffer(serialized, 66)


def _serialize_aggnonce(secp256k1: Secp256k1, aggnonce: Any) -> bytes:
    serialized = ctypes.create_string_buffer(66)
    try:
        if (
            secp256k1.lib.secp256k1_musig_aggnonce_serialize(
                secp256k1.ctx.verify, serialized, aggnonce
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 could not serialize the MuSig2 aggregate nonce")
        return serialized.raw
    finally:
        _zero_buffer(serialized, 66)


def _serialize_partial_sig(secp256k1: Secp256k1, partial_sig: Any) -> bytes:
    serialized = ctypes.create_string_buffer(32)
    try:
        if (
            secp256k1.lib.secp256k1_musig_partial_sig_serialize(
                secp256k1.ctx.verify, serialized, partial_sig
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 could not serialize the MuSig2 partial signature")
        return serialized.raw
    finally:
        _zero_buffer(serialized, 32)


def _serialize_pubkey(secp256k1: Secp256k1, pubkey: Any) -> bytes:
    serialized = ctypes.create_string_buffer(33)
    size = ctypes.c_size_t(33)
    try:
        if (
            secp256k1.lib.secp256k1_ec_pubkey_serialize(
                secp256k1.ctx.verify,
                serialized,
                ctypes.byref(size),
                pubkey,
                SECP256K1_EC_COMPRESSED,
            )
            != 1
            or size.value != 33
        ):
            raise MuSig2Error("libsecp256k1 could not serialize the aggregate public key")
        return serialized.raw
    finally:
        _zero_buffer(serialized, 33)


def _serialize_xonly_pubkey(secp256k1: Secp256k1, pubkey: Any) -> bytes:
    xonly = ctypes.create_string_buffer(64)
    serialized = ctypes.create_string_buffer(32)
    try:
        if (
            secp256k1.lib.secp256k1_xonly_pubkey_from_pubkey(
                secp256k1.ctx.verify, xonly, None, pubkey
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 could not convert the aggregate public key")
        if (
            secp256k1.lib.secp256k1_xonly_pubkey_serialize(secp256k1.ctx.verify, serialized, xonly)
            != 1
        ):
            raise MuSig2Error("libsecp256k1 could not serialize the aggregate x-only key")
        return serialized.raw
    finally:
        _zero_buffer(xonly, 64)
        _zero_buffer(serialized, 32)


def _opaque_ptr_array(buffers: Sequence[Any]) -> Any:
    pointers = (ctypes.c_void_p * len(buffers))()
    for index, buffer in enumerate(buffers):
        pointers[index] = ctypes.addressof(buffer)
    return pointers


class KeyAggContext:
    """BIP327 key aggregation state, backed by a native opaque cache."""

    __slots__ = ("_cache", "_participants", "_aggregate_xonly", "_aggregate_pubkey")

    def __init__(
        self,
        cache: Any,
        participants: Tuple[bytes, ...],
        aggregate_xonly: bytes,
        aggregate_pubkey: bytes,
    ) -> None:
        self._cache = cache
        self._participants = participants
        self._aggregate_xonly = aggregate_xonly
        self._aggregate_pubkey = aggregate_pubkey

    def aggregate_xonly(self) -> bytes:
        """The 32-byte BIP340 aggregate public key."""

        return self._aggregate_xonly

    def aggregate_pubkey(self) -> bytes:
        """The compressed 33-byte aggregate public key."""

        return self._aggregate_pubkey

    def _copy_cache(self) -> Any:
        copied = ctypes.create_string_buffer(KEYAGG_CACHE_SIZE)
        ctypes.memmove(copied, self._cache, KEYAGG_CACHE_SIZE)
        return copied


class Session:
    """Native MuSig2 signing session bound to its participants and context."""

    __slots__ = ("ctx", "_session", "_participants")

    def __init__(self, ctx: KeyAggContext, session: Any, participants: Tuple[bytes, ...]) -> None:
        self.ctx = ctx
        self._session = session
        self._participants = participants


class SecNonce:
    """A single-use native MuSig2 secret nonce.

    The native secnonce structure is never serialized or exposed. It is wiped
    after every signing attempt, including one that raises an exception.
    Obtain instances from nonce_gen, not this constructor. Do not fork or
    restore a process snapshot containing a live nonce: that copies its state.
    """

    __slots__ = ("__buffer", "__pubkey", "__used", "__lock")

    def __init__(self, buffer: Any, pubkey: bytes) -> None:
        self.__buffer = buffer
        self.__pubkey = pubkey
        self.__used = False
        self.__lock = threading.Lock()

    def __repr__(self) -> str:
        return "SecNonce(<redacted>)"

    __str__ = __repr__

    def __copy__(self) -> "SecNonce":
        raise TypeError("SecNonce instances cannot be copied")

    def __deepcopy__(self, memo: object) -> "SecNonce":
        raise TypeError("SecNonce instances cannot be copied")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("SecNonce instances cannot be pickled")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        raise TypeError("SecNonce instances cannot be pickled")

    def __getstate__(self) -> object:
        raise TypeError("SecNonce instances cannot be pickled")

    def __del__(self) -> None:
        try:
            _zero_buffer(self.__buffer, SECNONCE_SIZE)
        except (AttributeError, TypeError):
            pass

    def _sign(self, privkey: object, session: object) -> bytes:
        with self.__lock:
            if self.__used:
                raise MuSig2Error("MuSig2 secret nonce has already been consumed")
            self.__used = True

            keypair = signer_pubkey = partial_sig = None
            try:
                keypair = ctypes.create_string_buffer(96)
                signer_pubkey = ctypes.create_string_buffer(64)
                partial_sig = ctypes.create_string_buffer(PARTIAL_SIG_SIZE)
                secp256k1 = _require_musig()
                if not isinstance(session, Session):
                    raise MuSig2Error("session must be a MuSig2 Session")

                secret = _validate_scalar(secp256k1, privkey, "privkey")
                if secp256k1.lib.secp256k1_keypair_create(secp256k1.ctx.sign, keypair, secret) != 1:
                    raise MuSig2Error("libsecp256k1 could not create a keypair")
                if (
                    secp256k1.lib.secp256k1_ec_pubkey_create(
                        secp256k1.ctx.sign, signer_pubkey, secret
                    )
                    != 1
                ):
                    raise MuSig2Error("libsecp256k1 could not derive the signer public key")

                signer_serialized = _serialize_pubkey(secp256k1, signer_pubkey)
                if signer_serialized != self.__pubkey:
                    raise MuSig2Error("MuSig2 secret nonce is bound to a different public key")
                if signer_serialized not in session._participants:
                    raise MuSig2Error("signer public key is not a session participant")

                if (
                    secp256k1.lib.secp256k1_musig_partial_sign(
                        secp256k1.ctx.sign,
                        partial_sig,
                        self.__buffer,
                        keypair,
                        session.ctx._cache,
                        session._session,
                    )
                    != 1
                ):
                    raise MuSig2Error("libsecp256k1 MuSig2 partial signing failed")
                return _serialize_partial_sig(secp256k1, partial_sig)
            finally:
                _zero_buffer(self.__buffer, SECNONCE_SIZE)
                if partial_sig is not None:
                    _zero_buffer(partial_sig, PARTIAL_SIG_SIZE)
                if signer_pubkey is not None:
                    _zero_buffer(signer_pubkey, 64)
                if keypair is not None:
                    _zero_buffer(keypair, 96)


def key_agg(pubkeys: Sequence[bytes]) -> KeyAggContext:
    """Aggregate compressed BIP327 participant public keys without sorting them."""

    secp256k1 = _require_musig()
    values = _require_bytes_sequence(pubkeys, "pubkeys")
    parsed: list[Any] = []
    participants: list[bytes] = []
    cache = ctypes.create_string_buffer(KEYAGG_CACHE_SIZE)
    aggregate_xonly = ctypes.create_string_buffer(64)
    aggregate_pubkey = ctypes.create_string_buffer(64)
    try:
        for index, value in enumerate(values):
            participant, parsed_pubkey = _parse_pubkey(secp256k1, value, f"pubkeys[{index}]")
            participants.append(participant)
            parsed.append(parsed_pubkey)

        if (
            secp256k1.lib.secp256k1_musig_pubkey_agg(
                secp256k1.ctx.verify,
                aggregate_xonly,
                cache,
                _opaque_ptr_array(parsed),
                len(parsed),
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 MuSig2 key aggregation failed")
        if (
            secp256k1.lib.secp256k1_musig_pubkey_get(secp256k1.ctx.verify, aggregate_pubkey, cache)
            != 1
        ):
            raise MuSig2Error("libsecp256k1 could not retrieve the aggregate public key")

        serialized_xonly = ctypes.create_string_buffer(32)
        try:
            if (
                secp256k1.lib.secp256k1_xonly_pubkey_serialize(
                    secp256k1.ctx.verify, serialized_xonly, aggregate_xonly
                )
                != 1
            ):
                raise MuSig2Error("libsecp256k1 could not serialize the aggregate x-only key")
            return KeyAggContext(
                cache,
                tuple(participants),
                serialized_xonly.raw,
                _serialize_pubkey(secp256k1, aggregate_pubkey),
            )
        finally:
            _zero_buffer(serialized_xonly, 32)
    except Exception:
        _zero_buffer(cache, KEYAGG_CACHE_SIZE)
        raise
    finally:
        _zero_buffer(aggregate_xonly, 64)
        _zero_buffer(aggregate_pubkey, 64)
        for parsed_pubkey in parsed:
            _zero_buffer(parsed_pubkey, 64)


def apply_xonly_tweak(ctx: KeyAggContext, tweak: bytes) -> KeyAggContext:
    """Return a new aggregation context with a BIP341-compatible x-only tweak."""

    secp256k1 = _require_musig()
    if not isinstance(ctx, KeyAggContext):
        raise MuSig2Error("ctx must be a KeyAggContext")
    tweak_value = _require_bytes(tweak, 32, "tweak")
    cache = ctx._copy_cache()
    aggregate_pubkey = ctypes.create_string_buffer(64)
    try:
        if (
            secp256k1.lib.secp256k1_musig_pubkey_xonly_tweak_add(
                secp256k1.ctx.verify, aggregate_pubkey, cache, tweak_value
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 MuSig2 x-only tweak failed")
        return KeyAggContext(
            cache,
            ctx._participants,
            _serialize_xonly_pubkey(secp256k1, aggregate_pubkey),
            _serialize_pubkey(secp256k1, aggregate_pubkey),
        )
    except Exception:
        _zero_buffer(cache, KEYAGG_CACHE_SIZE)
        raise
    finally:
        _zero_buffer(aggregate_pubkey, 64)


def nonce_gen(pubkey: bytes, rand: bytes | None = None) -> Tuple[SecNonce, bytes]:
    """Generate a single-use secret nonce and its 66-byte public nonce.

    Omit rand to use fresh operating-system randomness. If supplied, rand must
    be 32 uniformly random SECRET bytes, unique to this call even if signing
    fails or is abandoned. It is not public auxiliary randomness. Repeating
    it for the same pubkey repeats the nonce and can expose the private key.
    The caller's immutable rand bytes cannot be wiped by this function.
    """

    secp256k1 = _require_musig()
    participant, parsed_pubkey = _parse_pubkey(secp256k1, pubkey, "pubkey")
    random_bytes = os.urandom(32) if rand is None else _require_bytes(rand, 32, "rand")
    session_secrand = ctypes.create_string_buffer(random_bytes, 32)
    secnonce = ctypes.create_string_buffer(SECNONCE_SIZE)
    pubnonce = ctypes.create_string_buffer(PUBNONCE_SIZE)
    success = False
    try:
        if (
            secp256k1.lib.secp256k1_musig_nonce_gen(
                secp256k1.ctx.sign,
                secnonce,
                pubnonce,
                session_secrand,
                None,
                parsed_pubkey,
                None,
                None,
                None,
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 MuSig2 nonce generation failed")
        serialized = _serialize_pubnonce(secp256k1, pubnonce)
        result = SecNonce(secnonce, participant)
        success = True
        return result, serialized
    finally:
        _zero_buffer(session_secrand, 32)
        _zero_buffer(parsed_pubkey, 64)
        _zero_buffer(pubnonce, PUBNONCE_SIZE)
        if not success:
            _zero_buffer(secnonce, SECNONCE_SIZE)


def nonce_agg(pubnonces: Sequence[bytes]) -> bytes:
    """Aggregate 66-byte MuSig2 public nonces."""

    secp256k1 = _require_musig()
    values = _require_bytes_sequence(pubnonces, "pubnonces")
    parsed: list[Any] = []
    aggregate = ctypes.create_string_buffer(AGGNONCE_SIZE)
    try:
        for index, value in enumerate(values):
            parsed.append(_parse_pubnonce(secp256k1, value, f"pubnonces[{index}]"))
        if (
            secp256k1.lib.secp256k1_musig_nonce_agg(
                secp256k1.ctx.verify, aggregate, _opaque_ptr_array(parsed), len(parsed)
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 MuSig2 nonce aggregation failed")
        return _serialize_aggnonce(secp256k1, aggregate)
    finally:
        _zero_buffer(aggregate, AGGNONCE_SIZE)
        for parsed_nonce in parsed:
            _zero_buffer(parsed_nonce, PUBNONCE_SIZE)


def get_session(
    aggnonce: bytes,
    pubkeys: Sequence[bytes],
    tweaks: Sequence[bytes],
    msg32: bytes,
) -> Session:
    """Create a signing session from its aggregate nonce and ordered key setup."""

    secp256k1 = _require_musig()
    message = _require_bytes(msg32, 32, "msg32")
    ctx = key_agg(pubkeys)
    if not isinstance(tweaks, Sequence) or isinstance(tweaks, (bytes, bytearray, str)):
        raise MuSig2Error("tweaks must be a sequence of bytes")
    for index, tweak in enumerate(tweaks):
        ctx = apply_xonly_tweak(ctx, _require_bytes(tweak, 32, f"tweaks[{index}]"))

    parsed_aggnonce = _parse_aggnonce(secp256k1, aggnonce, "aggnonce")
    native_session = ctypes.create_string_buffer(SESSION_SIZE)
    try:
        if (
            secp256k1.lib.secp256k1_musig_nonce_process(
                secp256k1.ctx.sign, native_session, parsed_aggnonce, message, ctx._cache
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 MuSig2 session creation failed")
        return Session(ctx, native_session, ctx._participants)
    except Exception:
        _zero_buffer(native_session, SESSION_SIZE)
        raise
    finally:
        _zero_buffer(parsed_aggnonce, AGGNONCE_SIZE)


def sign_partial(secnonce: SecNonce, privkey: bytes, session: Session) -> bytes:
    """Create a partial signature and irrevocably consume ``secnonce``.

    Verify the result with partial_sig_verify before sharing it. The native
    signing function does not perform this recommended fault-detection check.
    """

    if not isinstance(secnonce, SecNonce):
        raise MuSig2Error("secnonce must be a SecNonce")
    return secnonce._sign(privkey, session)


def partial_sig_verify(psig: bytes, pubnonce: bytes, pubkey: bytes, session: Session) -> bool:
    """Verify a participant's 32-byte partial signature for ``session``.

    Malformed contributions or an invalid session argument raise MuSig2Error.
    Well-formed contributions return False if verification fails or the public
    key is not a session participant. Coordinators should handle MuSig2Error
    for each peer's contribution separately.
    """

    secp256k1 = _require_musig()
    if not isinstance(session, Session):
        raise MuSig2Error("session must be a MuSig2 Session")
    participant, parsed_pubkey = _parse_pubkey(secp256k1, pubkey, "pubkey")
    parsed_pubnonce = _parse_pubnonce(secp256k1, pubnonce, "pubnonce")
    parsed_psig = _parse_partial_sig(secp256k1, psig, "psig")
    try:
        if participant not in session._participants:
            return False
        return bool(
            secp256k1.lib.secp256k1_musig_partial_sig_verify(
                secp256k1.ctx.verify,
                parsed_psig,
                parsed_pubnonce,
                parsed_pubkey,
                session.ctx._cache,
                session._session,
            )
            == 1
        )
    finally:
        _zero_buffer(parsed_psig, PARTIAL_SIG_SIZE)
        _zero_buffer(parsed_pubnonce, PUBNONCE_SIZE)
        _zero_buffer(parsed_pubkey, 64)


def partial_sig_agg(psigs: Sequence[bytes], session: Session) -> bytes:
    """Aggregate one partial signature per session participant into a BIP340 signature.

    This does not verify the contributions or the result. Verify the returned
    signature against the session's aggregate x-only key and message.
    """

    secp256k1 = _require_musig()
    if not isinstance(session, Session):
        raise MuSig2Error("session must be a MuSig2 Session")
    values = _require_bytes_sequence(psigs, "psigs")
    if len(values) != len(session._participants):
        raise MuSig2Error("psigs must contain exactly one signature per session participant")

    parsed: list[Any] = []
    signature = ctypes.create_string_buffer(64)
    try:
        for index, value in enumerate(values):
            parsed.append(_parse_partial_sig(secp256k1, value, f"psigs[{index}]"))
        if (
            secp256k1.lib.secp256k1_musig_partial_sig_agg(
                secp256k1.ctx.verify,
                signature,
                session._session,
                _opaque_ptr_array(parsed),
                len(parsed),
            )
            != 1
        ):
            raise MuSig2Error("libsecp256k1 MuSig2 partial signature aggregation failed")
        return signature.raw
    finally:
        _zero_buffer(signature, 64)
        for parsed_sig in parsed:
            _zero_buffer(parsed_sig, PARTIAL_SIG_SIZE)


__all__ = (
    "MuSig2Error",
    "KeyAggContext",
    "SecNonce",
    "Session",
    "key_agg",
    "apply_xonly_tweak",
    "nonce_gen",
    "nonce_agg",
    "get_session",
    "sign_partial",
    "partial_sig_verify",
    "partial_sig_agg",
)
