# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import copy
import ctypes
import json
import pickle
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast
from unittest.mock import patch

from bitcointx.core.key import CKey, XOnlyPubKey
from bitcointx.core.musig import (
    MuSig2Error,
    SecNonce,
    Session,
    apply_xonly_tweak,
    get_session,
    key_agg,
    nonce_agg,
    nonce_gen,
    partial_sig_agg,
    partial_sig_verify,
    sign_partial,
)
from bitcointx.core.secp256k1 import (
    _MUSIG_FUNCTION_NAMES,
    _add_musig_function_definitions,
    get_secp256k1,
)


def _hex(value: str) -> bytes:
    return bytes.fromhex(value)


HAS_MUSIG = get_secp256k1().cap.has_musig


class TestMuSig2Capability(unittest.TestCase):
    def test_capability_requires_every_musig_symbol(self) -> None:
        symbols = {name: SimpleNamespace() for name in _MUSIG_FUNCTION_NAMES[:-1]}
        partial_library = cast(ctypes.CDLL, SimpleNamespace(**symbols))
        self.assertFalse(_add_musig_function_definitions(partial_library))

    def test_missing_capability_fails_clearly(self) -> None:
        unavailable = SimpleNamespace(cap=SimpleNamespace(has_musig=False))
        with patch("bitcointx.core.musig.get_secp256k1", return_value=unavailable):
            with self.assertRaisesRegex(MuSig2Error, "--enable-module-musig"):
                key_agg([b"\x02" + b"\x01" * 32])


@unittest.skipUnless(HAS_MUSIG, "libsecp256k1 was not built with the musig module")
class TestMuSig2(unittest.TestCase):
    vectors: ClassVar[dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        vectors_path = Path(__file__).with_name("data") / "bip327-musig2-vectors.json"
        cls.vectors = json.loads(vectors_path.read_text(encoding="ascii"))

    def _two_party_session(
        self,
    ) -> tuple[
        list[CKey],
        list[bytes],
        bytes,
        tuple[Session, SecNonce, SecNonce],
        bytes,
        bytes,
    ]:
        keys = [
            CKey(b"\x00" * 31 + b"\x01"),
            CKey(b"\x00" * 31 + b"\x02"),
        ]
        pubkeys = [bytes(key.pub) for key in keys]
        secnonce_one, pubnonce_one = nonce_gen(pubkeys[0])
        secnonce_two, pubnonce_two = nonce_gen(pubkeys[1])
        message = b"\x33" * 32
        session = get_session(nonce_agg([pubnonce_one, pubnonce_two]), pubkeys, [], message)
        return (
            keys,
            pubkeys,
            message,
            (session, secnonce_one, secnonce_two),
            pubnonce_one,
            pubnonce_two,
        )

    def test_official_key_aggregation_vectors(self) -> None:
        vectors = self.vectors["key_agg"]
        pubkeys = [_hex(value) for value in vectors["pubkeys"]]
        for case in vectors["test_cases"]:
            ctx = key_agg([pubkeys[index] for index in case["key_indices"]])
            self.assertEqual(ctx.aggregate_xonly(), _hex(case["expected"]))
            self.assertEqual(len(ctx.aggregate_pubkey()), 33)

    def test_official_nonce_vectors(self) -> None:
        nonce_gen_vector = self.vectors["nonce_gen"]
        _, pubnonce = nonce_gen(_hex(nonce_gen_vector["pubkey"]), _hex(nonce_gen_vector["rand"]))
        self.assertEqual(pubnonce, _hex(nonce_gen_vector["expected_pubnonce"]))

        nonce_agg_vector = self.vectors["nonce_agg"]
        self.assertEqual(
            nonce_agg([_hex(value) for value in nonce_agg_vector["pubnonces"]]),
            _hex(nonce_agg_vector["expected"]),
        )

    def test_official_nonce_coefficient_partial_signature_vector(self) -> None:
        vector = self.vectors["nonce_coefficient_partial_verify"]
        pubkeys = [_hex(value) for value in vector["pubkeys"]]
        pubnonces = [_hex(value) for value in vector["pubnonces"]]
        session = get_session(_hex(vector["aggnonce"]), pubkeys, [], _hex(vector["msg"]))
        self.assertTrue(
            partial_sig_verify(
                _hex(vector["psig"]),
                pubnonces[vector["pubnonce_index"]],
                pubkeys[vector["pubkey_index"]],
                session,
            )
        )

        tweak_vector = self.vectors["xonly_tweak_partial_verify"]
        tweak_pubkeys = [_hex(value) for value in tweak_vector["pubkeys"]]
        tweak_pubnonces = [_hex(value) for value in tweak_vector["pubnonces"]]
        tweak_session = get_session(
            _hex(tweak_vector["aggnonce"]),
            tweak_pubkeys,
            [_hex(tweak_vector["tweak"])],
            _hex(tweak_vector["msg"]),
        )
        self.assertTrue(
            partial_sig_verify(
                _hex(tweak_vector["psig"]),
                tweak_pubnonces[tweak_vector["pubnonce_index"]],
                tweak_pubkeys[tweak_vector["pubkey_index"]],
                tweak_session,
            )
        )

    def test_official_partial_signature_aggregation_vector(self) -> None:
        vector = self.vectors["signature_agg"]
        session = get_session(
            _hex(vector["aggnonce"]),
            [_hex(value) for value in vector["pubkeys"]],
            [],
            _hex(vector["msg"]),
        )
        self.assertEqual(
            partial_sig_agg([_hex(value) for value in vector["psigs"]], session),
            _hex(vector["expected"]),
        )
        self.assertTrue(
            XOnlyPubKey(session.ctx.aggregate_xonly()).verify_schnorr(
                _hex(vector["msg"]), _hex(vector["expected"])
            )
        )

    def test_zero_xonly_tweak_matches_independent_expected_key(self) -> None:
        key_agg_vector = self.vectors["key_agg"]
        zero_tweak_vector = self.vectors["zero_xonly_tweak"]
        pubkeys = [_hex(value) for value in key_agg_vector["pubkeys"]]
        ctx = key_agg([pubkeys[index] for index in zero_tweak_vector["key_indices"]])
        self.assertEqual(ctx.aggregate_pubkey()[0], 3)

        tweaked_ctx = apply_xonly_tweak(ctx, _hex(zero_tweak_vector["tweak"]))
        self.assertEqual(tweaked_ctx.aggregate_xonly(), _hex(zero_tweak_vector["expected_xonly"]))
        self.assertEqual(tweaked_ctx.aggregate_pubkey(), _hex(zero_tweak_vector["expected_pubkey"]))

    def test_two_party_tweaked_signature_verifies(self) -> None:
        keys = [
            CKey(b"\x00" * 31 + b"\x01"),
            CKey(b"\x00" * 31 + b"\x02"),
        ]
        pubkeys = [bytes(key.pub) for key in keys]
        tweak = b"\x00" * 31 + b"\x03"
        direct_ctx = apply_xonly_tweak(key_agg(pubkeys), tweak)
        secnonce_one, pubnonce_one = nonce_gen(pubkeys[0])
        secnonce_two, pubnonce_two = nonce_gen(pubkeys[1])
        message = b"\x33" * 32
        session = get_session(nonce_agg([pubnonce_one, pubnonce_two]), pubkeys, [tweak], message)
        psig_one = sign_partial(secnonce_one, bytes(keys[0]), session)
        psig_two = sign_partial(secnonce_two, bytes(keys[1]), session)

        self.assertEqual(session.ctx.aggregate_xonly(), direct_ctx.aggregate_xonly())
        self.assertTrue(partial_sig_verify(psig_one, pubnonce_one, pubkeys[0], session))
        self.assertTrue(partial_sig_verify(psig_two, pubnonce_two, pubkeys[1], session))
        signature = partial_sig_agg([psig_one, psig_two], session)
        self.assertTrue(
            XOnlyPubKey(session.ctx.aggregate_xonly()).verify_schnorr(message, signature)
        )

    def test_zero_xonly_tweak_full_signing(self) -> None:
        keys = [
            CKey(b"\x00" * 31 + b"\x01"),
            CKey(b"\x00" * 31 + b"\x02"),
        ]
        pubkeys = [bytes(key.pub) for key in keys]
        tweak = b"\x00" * 32
        direct_ctx = apply_xonly_tweak(key_agg(pubkeys), tweak)
        secnonce_one, pubnonce_one = nonce_gen(pubkeys[0])
        secnonce_two, pubnonce_two = nonce_gen(pubkeys[1])
        message = b"\x99" * 32
        session = get_session(nonce_agg([pubnonce_one, pubnonce_two]), pubkeys, [tweak], message)
        psig_one = sign_partial(secnonce_one, bytes(keys[0]), session)
        psig_two = sign_partial(secnonce_two, bytes(keys[1]), session)
        signature = partial_sig_agg([psig_one, psig_two], session)

        self.assertEqual(session.ctx.aggregate_xonly(), direct_ctx.aggregate_xonly())
        self.assertTrue(
            XOnlyPubKey(session.ctx.aggregate_xonly()).verify_schnorr(message, signature)
        )

    def test_duplicate_participants_and_partial_count(self) -> None:
        key = CKey(b"\x00" * 31 + b"\x01")
        pubkey = bytes(key.pub)
        secnonce_one, pubnonce_one = nonce_gen(pubkey)
        secnonce_two, pubnonce_two = nonce_gen(pubkey)
        message = b"\x66" * 32
        session = get_session(
            nonce_agg([pubnonce_one, pubnonce_two]), [pubkey, pubkey], [], message
        )
        psig_one = sign_partial(secnonce_one, bytes(key), session)
        psig_two = sign_partial(secnonce_two, bytes(key), session)
        signature = partial_sig_agg([psig_one, psig_two], session)
        self.assertTrue(
            XOnlyPubKey(session.ctx.aggregate_xonly()).verify_schnorr(message, signature)
        )
        with self.assertRaises(MuSig2Error):
            partial_sig_agg([psig_one], session)

    def test_invalid_encodings_are_rejected_before_session_use(self) -> None:
        key = CKey(b"\x00" * 31 + b"\x01")
        pubkey = bytes(key.pub)
        with self.assertRaises(MuSig2Error):
            key_agg([])
        with self.assertRaises(MuSig2Error):
            key_agg([b"\x04" + pubkey[1:]])
        with self.assertRaises(MuSig2Error):
            nonce_agg([b"\x00" * 65])
        with self.assertRaises(MuSig2Error):
            get_session(b"\x00" * 66, [pubkey], [], b"\x00" * 31)

        _, _, _, session_data, pubnonce_one, _ = self._two_party_session()
        session, _, _ = session_data
        with self.assertRaises(MuSig2Error):
            partial_sig_verify(b"\xff" * 32, pubnonce_one, pubkey, session)

    def test_well_formed_invalid_partial_signature_returns_false(self) -> None:
        _, pubkeys, _, session_data, pubnonce, _ = self._two_party_session()
        session, _, _ = session_data
        self.assertFalse(partial_sig_verify(bytes(32), pubnonce, pubkeys[0], session))

    def test_secret_nonce_is_single_use_and_nonserializable(self) -> None:
        keys, pubkeys, _, session_data, _, _ = self._two_party_session()
        session, secnonce_one, _ = session_data
        self.assertEqual(repr(secnonce_one), "SecNonce(<redacted>)")
        with self.assertRaises(TypeError):
            copy.copy(secnonce_one)
        with self.assertRaises(TypeError):
            copy.deepcopy(secnonce_one)
        with self.assertRaises(TypeError):
            pickle.dumps(secnonce_one)

        with self.assertRaises(MuSig2Error):
            sign_partial(secnonce_one, bytes(keys[1]), session)
        with self.assertRaisesRegex(MuSig2Error, "already been consumed"):
            sign_partial(secnonce_one, bytes(keys[0]), session)

    def test_secret_nonce_consumption_is_thread_safe(self) -> None:
        keys, _, _, session_data, _, _ = self._two_party_session()
        session, secnonce_one, _ = session_data
        barrier = threading.Barrier(2)

        def attempt() -> bytes | None:
            barrier.wait()
            try:
                return sign_partial(secnonce_one, bytes(keys[0]), session)
            except MuSig2Error:
                return None

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(outcome is not None for outcome in outcomes), 1)

    def test_secret_nonce_is_wiped_when_signing_allocation_fails(self) -> None:
        create_buffer = ctypes.create_string_buffer
        for fail_at in (1, 2, 3):
            with self.subTest(allocation=fail_at):
                keys, _, _, session_data, _, _ = self._two_party_session()
                session, secnonce, _ = session_data
                nonce_buffer = cast(Any, secnonce)._SecNonce__buffer
                self.assertTrue(any(nonce_buffer.raw))
                allocated: list[Any] = []

                def allocate(size: int) -> Any:
                    if len(allocated) + 1 == fail_at:
                        raise MemoryError("injected allocation failure")
                    buffer = create_buffer(size)
                    # Nonzero contents distinguish cleanup from initial zero allocation.
                    ctypes.memset(buffer, 0x7F, size)
                    allocated.append(buffer)
                    return buffer

                with patch("bitcointx.core.musig.ctypes.create_string_buffer", side_effect=allocate):
                    with self.assertRaisesRegex(MemoryError, "injected allocation failure"):
                        sign_partial(secnonce, bytes(keys[0]), session)

                self.assertEqual(nonce_buffer.raw, bytes(ctypes.sizeof(nonce_buffer)))
                for buffer in allocated:
                    self.assertEqual(buffer.raw, bytes(ctypes.sizeof(buffer)))
                with self.assertRaisesRegex(MuSig2Error, "already been consumed"):
                    sign_partial(secnonce, bytes(keys[0]), session)


if __name__ == "__main__":
    unittest.main()
