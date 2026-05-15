# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

"""Unit tests for the libsecp256k1 v0.7 compatibility shim.

These tests use a fake ``ctypes.CDLL``-like object so that we can verify the
function-binding logic in :func:`_add_function_definitions` independently of
which libsecp256k1 happens to be installed on the test runner. See
https://github.com/Simplexum/python-bitcointx/issues/88.
"""

import ctypes
import unittest
from typing import Any

from bitcointx.core.secp256k1 import _add_function_definitions


class _FakeFunc:
    """Minimal stand-in for a ctypes-bound C function."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.restype: Any = None
        self.argtypes: Any = None


class _FakeLib:
    """Fake CDLL exporting only the symbols listed in ``exports``.

    Attribute access to any other name returns ``None`` from :func:`getattr`
    (mirroring how ``getattr(lib, 'unknown', None)`` behaves in the real code),
    and a direct attribute access raises :class:`AttributeError`.
    """

    def __init__(self, exports: set[str]) -> None:
        self._exports = exports
        for name in exports:
            object.__setattr__(self, name, _FakeFunc(name))

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(name)


# Minimum set of unconditional symbols that ``_add_function_definitions``
# always assigns argtypes/restype to, regardless of libsecp256k1 version.
_CORE_SYMBOLS = {
    "secp256k1_context_create",
    "secp256k1_context_randomize",
    "secp256k1_context_set_illegal_callback",
    "secp256k1_ecdsa_sign",
    "secp256k1_ecdsa_signature_serialize_der",
    "secp256k1_ec_pubkey_create",
    "secp256k1_ec_seckey_verify",
    "secp256k1_ecdsa_signature_parse_der",
    "secp256k1_ecdsa_signature_parse_compact",
    "secp256k1_ecdsa_signature_normalize",
    "secp256k1_ecdsa_verify",
    "secp256k1_ec_pubkey_parse",
    "secp256k1_ec_pubkey_tweak_add",
    "secp256k1_ec_pubkey_serialize",
    "secp256k1_ec_pubkey_combine",
}


class Test_Secp256k1_v07_Compat(unittest.TestCase):
    def test_legacy_privkey_symbol(self) -> None:
        """Pre-v0.7 libsecp256k1 only exports `secp256k1_ec_privkey_tweak_add`."""
        lib = _FakeLib(_CORE_SYMBOLS | {"secp256k1_ec_privkey_tweak_add"})

        _add_function_definitions(lib)  # type: ignore[arg-type]

        # Both spellings must resolve to the same underlying function and be
        # fully typed.
        self.assertIs(lib.secp256k1_ec_privkey_tweak_add, lib.secp256k1_ec_seckey_tweak_add)
        self.assertEqual(lib.secp256k1_ec_privkey_tweak_add.restype, ctypes.c_int)

    def test_modern_seckey_symbol(self) -> None:
        """v0.7+ libsecp256k1 only exports `secp256k1_ec_seckey_tweak_add`."""
        lib = _FakeLib(_CORE_SYMBOLS | {"secp256k1_ec_seckey_tweak_add"})

        _add_function_definitions(lib)  # type: ignore[arg-type]

        self.assertIs(lib.secp256k1_ec_privkey_tweak_add, lib.secp256k1_ec_seckey_tweak_add)
        self.assertEqual(lib.secp256k1_ec_seckey_tweak_add.restype, ctypes.c_int)

    def test_both_symbols_present_prefers_modern(self) -> None:
        """If both spellings are exported, the modern `seckey` name wins."""
        lib = _FakeLib(
            _CORE_SYMBOLS
            | {
                "secp256k1_ec_privkey_tweak_add",
                "secp256k1_ec_seckey_tweak_add",
            }
        )
        modern = lib.secp256k1_ec_seckey_tweak_add

        _add_function_definitions(lib)  # type: ignore[arg-type]

        self.assertIs(lib.secp256k1_ec_privkey_tweak_add, modern)
        self.assertIs(lib.secp256k1_ec_seckey_tweak_add, modern)

    def test_seckey_negate_alias(self) -> None:
        """`secp256k1_ec_seckey_negate` (v0.7+) is aliased to the privkey name."""
        lib = _FakeLib(
            _CORE_SYMBOLS
            | {
                "secp256k1_ec_privkey_tweak_add",
                "secp256k1_ec_seckey_negate",
            }
        )

        cap = _add_function_definitions(lib)  # type: ignore[arg-type]

        self.assertTrue(cap.has_privkey_negate)
        self.assertIs(lib.secp256k1_ec_privkey_negate, lib.secp256k1_ec_seckey_negate)


if __name__ == "__main__":
    unittest.main()
