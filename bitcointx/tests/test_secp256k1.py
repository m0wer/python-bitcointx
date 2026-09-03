# Copyright (C) 2026 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.

import ctypes
import unittest
from types import SimpleNamespace
from typing import cast

from bitcointx.core.secp256k1 import _get_schnorrsig_sign_function


class TestSchnorrSignCompatibility(unittest.TestCase):
    def test_prefers_sign32(self) -> None:
        sign32 = object()
        legacy_sign = object()
        lib = cast(ctypes.CDLL, SimpleNamespace(
            secp256k1_schnorrsig_sign32=sign32,
            secp256k1_schnorrsig_sign=legacy_sign,
        ))

        self.assertIs(_get_schnorrsig_sign_function(lib), sign32)

    def test_falls_back_to_legacy_sign(self) -> None:
        legacy_sign = object()
        lib = cast(ctypes.CDLL, SimpleNamespace(
            secp256k1_schnorrsig_sign=legacy_sign,
        ))

        self.assertIs(_get_schnorrsig_sign_function(lib), legacy_sign)

    def test_returns_none_without_compatible_symbol(self) -> None:
        lib = cast(ctypes.CDLL, SimpleNamespace())

        self.assertIsNone(_get_schnorrsig_sign_function(lib))
