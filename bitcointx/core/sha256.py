# Copyright (C) 2018 The python-bitcointx developers
#
# This file is part of python-bitcointx.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcointx, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.
#
# This code is ported from C++ code from Bitcoin Core.
# Original C++ code was Copyright (c) 2014-2017 The Bitcoin Core developers
# Original C++ code was licensed under MIT software license.

"""
This is needed for midstate SHA256, that is not available
from hashlib.sha256. Runtime performance will be slow, but oftentimes this
is acceptable. IMPORTANT: code is not constant-time! This should NOT be used
for working with # secret data, such as, for example  building a MAC (message
authentication code), etc.
"""

# pylama:ignore=E501

import struct
from typing import Union, List, TypeVar

SHA256_MAX = 0x1FFFFFFFFFFFFFFF


def Ch(x: int, y: int, z: int) -> int:
    return z ^ (x & (y ^ z))


def Maj(x: int, y: int, z: int) -> int:
    return (x & y) | (z & (x | y))


def Sigma0(x: int) -> int:
    return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10)


def Sigma1(x: int) -> int:
    return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7)


def sigma0(x: int) -> int:
    return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3)


def sigma1(x: int) -> int:
    return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10)


def uint32(x: int) -> int:
    return x & 0xFFFFFFFF


# One round of SHA-256.
def Round(
    a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, k: int, w: int, x: List[int]
) -> None:
    t1 = uint32(x[h] + Sigma1(x[e]) + Ch(x[e], x[f], x[g]) + k + w)
    t2 = uint32(Sigma0(x[a]) + Maj(x[a], x[b], x[c]))
    x[d] = uint32(x[d] + t1)
    x[h] = uint32(t1 + t2)


def ReadBE32(buf: bytes) -> int:
    return int(struct.unpack(b">I", buf[:4])[0])


T_CSHA256 = TypeVar("T_CSHA256", bound="CSHA256")


class CSHA256:
    """
    This class provides access to SHA256 routines, with access to
    SHA256 midstate (which is not available from hashlib.sha256)

    The code is not constant-time! This should NOT be used for working with
    secret data, such as, for example  building a MAC (message authentication
    code), etc.
    """

    __slots__ = ["s", "buf", "bytes_count"]

    buf: bytes
    bytes_count: int
    s: List[int]

    # Initialize SHA-256 state.
    def __init__(self) -> None:
        self.Reset()

    # Perform a number of SHA-256 transformations, processing 64-byte chunks.
    def Transform(self, chunk: Union[bytes, bytearray], blocks: int) -> None:
        if not isinstance(blocks, int):
            raise TypeError("blocks must be an instance of int")
        if not isinstance(chunk, (bytes, bytearray)):
            raise TypeError("chunk must be an instance of bytes or bytearray")
        s = self.s
        while blocks:
            blocks -= 1
            a, b, c, d, e, f, g, h = range(8)
            x = s.copy()

            w0 = ReadBE32(chunk[0:])
            Round(a, b, c, d, e, f, g, h, 0x428A2F98, w0, x)
            w1 = ReadBE32(chunk[4:])
            Round(h, a, b, c, d, e, f, g, 0x71374491, w1, x)
            w2 = ReadBE32(chunk[8:])
            Round(g, h, a, b, c, d, e, f, 0xB5C0FBCF, w2, x)
            w3 = ReadBE32(chunk[12:])
            Round(f, g, h, a, b, c, d, e, 0xE9B5DBA5, w3, x)
            w4 = ReadBE32(chunk[16:])
            Round(e, f, g, h, a, b, c, d, 0x3956C25B, w4, x)
            w5 = ReadBE32(chunk[20:])
            Round(d, e, f, g, h, a, b, c, 0x59F111F1, w5, x)
            w6 = ReadBE32(chunk[24:])
            Round(c, d, e, f, g, h, a, b, 0x923F82A4, w6, x)
            w7 = ReadBE32(chunk[28:])
            Round(b, c, d, e, f, g, h, a, 0xAB1C5ED5, w7, x)
            w8 = ReadBE32(chunk[32:])
            Round(a, b, c, d, e, f, g, h, 0xD807AA98, w8, x)
            w9 = ReadBE32(chunk[36:])
            Round(h, a, b, c, d, e, f, g, 0x12835B01, w9, x)
            w10 = ReadBE32(chunk[40:])
            Round(g, h, a, b, c, d, e, f, 0x243185BE, w10, x)
            w11 = ReadBE32(chunk[44:])
            Round(f, g, h, a, b, c, d, e, 0x550C7DC3, w11, x)
            w12 = ReadBE32(chunk[48:])
            Round(e, f, g, h, a, b, c, d, 0x72BE5D74, w12, x)
            w13 = ReadBE32(chunk[52:])
            Round(d, e, f, g, h, a, b, c, 0x80DEB1FE, w13, x)
            w14 = ReadBE32(chunk[56:])
            Round(c, d, e, f, g, h, a, b, 0x9BDC06A7, w14, x)
            w15 = ReadBE32(chunk[60:])
            Round(b, c, d, e, f, g, h, a, 0xC19BF174, w15, x)

            w0 = uint32(w0 + sigma1(w14) + w9 + sigma0(w1))
            Round(a, b, c, d, e, f, g, h, 0xE49B69C1, w0, x)
            w1 = uint32(w1 + sigma1(w15) + w10 + sigma0(w2))
            Round(h, a, b, c, d, e, f, g, 0xEFBE4786, w1, x)
            w2 = uint32(w2 + sigma1(w0) + w11 + sigma0(w3))
            Round(g, h, a, b, c, d, e, f, 0x0FC19DC6, w2, x)
            w3 = uint32(w3 + sigma1(w1) + w12 + sigma0(w4))
            Round(f, g, h, a, b, c, d, e, 0x240CA1CC, w3, x)
            w4 = uint32(w4 + sigma1(w2) + w13 + sigma0(w5))
            Round(e, f, g, h, a, b, c, d, 0x2DE92C6F, w4, x)
            w5 = uint32(w5 + sigma1(w3) + w14 + sigma0(w6))
            Round(d, e, f, g, h, a, b, c, 0x4A7484AA, w5, x)
            w6 = uint32(w6 + sigma1(w4) + w15 + sigma0(w7))
            Round(c, d, e, f, g, h, a, b, 0x5CB0A9DC, w6, x)
            w7 = uint32(w7 + sigma1(w5) + w0 + sigma0(w8))
            Round(b, c, d, e, f, g, h, a, 0x76F988DA, w7, x)
            w8 = uint32(w8 + sigma1(w6) + w1 + sigma0(w9))
            Round(a, b, c, d, e, f, g, h, 0x983E5152, w8, x)
            w9 = uint32(w9 + sigma1(w7) + w2 + sigma0(w10))
            Round(h, a, b, c, d, e, f, g, 0xA831C66D, w9, x)
            w10 = uint32(w10 + sigma1(w8) + w3 + sigma0(w11))
            Round(g, h, a, b, c, d, e, f, 0xB00327C8, w10, x)
            w11 = uint32(w11 + sigma1(w9) + w4 + sigma0(w12))
            Round(f, g, h, a, b, c, d, e, 0xBF597FC7, w11, x)
            w12 = uint32(w12 + sigma1(w10) + w5 + sigma0(w13))
            Round(e, f, g, h, a, b, c, d, 0xC6E00BF3, w12, x)
            w13 = uint32(w13 + sigma1(w11) + w6 + sigma0(w14))
            Round(d, e, f, g, h, a, b, c, 0xD5A79147, w13, x)
            w14 = uint32(w14 + sigma1(w12) + w7 + sigma0(w15))
            Round(c, d, e, f, g, h, a, b, 0x06CA6351, w14, x)
            w15 = uint32(w15 + sigma1(w13) + w8 + sigma0(w0))
            Round(b, c, d, e, f, g, h, a, 0x14292967, w15, x)

            w0 = uint32(w0 + sigma1(w14) + w9 + sigma0(w1))
            Round(a, b, c, d, e, f, g, h, 0x27B70A85, w0, x)
            w1 = uint32(w1 + sigma1(w15) + w10 + sigma0(w2))
            Round(h, a, b, c, d, e, f, g, 0x2E1B2138, w1, x)
            w2 = uint32(w2 + sigma1(w0) + w11 + sigma0(w3))
            Round(g, h, a, b, c, d, e, f, 0x4D2C6DFC, w2, x)
            w3 = uint32(w3 + sigma1(w1) + w12 + sigma0(w4))
            Round(f, g, h, a, b, c, d, e, 0x53380D13, w3, x)
            w4 = uint32(w4 + sigma1(w2) + w13 + sigma0(w5))
            Round(e, f, g, h, a, b, c, d, 0x650A7354, w4, x)
            w5 = uint32(w5 + sigma1(w3) + w14 + sigma0(w6))
            Round(d, e, f, g, h, a, b, c, 0x766A0ABB, w5, x)
            w6 = uint32(w6 + sigma1(w4) + w15 + sigma0(w7))
            Round(c, d, e, f, g, h, a, b, 0x81C2C92E, w6, x)
            w7 = uint32(w7 + sigma1(w5) + w0 + sigma0(w8))
            Round(b, c, d, e, f, g, h, a, 0x92722C85, w7, x)
            w8 = uint32(w8 + sigma1(w6) + w1 + sigma0(w9))
            Round(a, b, c, d, e, f, g, h, 0xA2BFE8A1, w8, x)
            w9 = uint32(w9 + sigma1(w7) + w2 + sigma0(w10))
            Round(h, a, b, c, d, e, f, g, 0xA81A664B, w9, x)
            w10 = uint32(w10 + sigma1(w8) + w3 + sigma0(w11))
            Round(g, h, a, b, c, d, e, f, 0xC24B8B70, w10, x)
            w11 = uint32(w11 + sigma1(w9) + w4 + sigma0(w12))
            Round(f, g, h, a, b, c, d, e, 0xC76C51A3, w11, x)
            w12 = uint32(w12 + sigma1(w10) + w5 + sigma0(w13))
            Round(e, f, g, h, a, b, c, d, 0xD192E819, w12, x)
            w13 = uint32(w13 + sigma1(w11) + w6 + sigma0(w14))
            Round(d, e, f, g, h, a, b, c, 0xD6990624, w13, x)
            w14 = uint32(w14 + sigma1(w12) + w7 + sigma0(w15))
            Round(c, d, e, f, g, h, a, b, 0xF40E3585, w14, x)
            w15 = uint32(w15 + sigma1(w13) + w8 + sigma0(w0))
            Round(b, c, d, e, f, g, h, a, 0x106AA070, w15, x)

            w0 = uint32(w0 + sigma1(w14) + w9 + sigma0(w1))
            Round(a, b, c, d, e, f, g, h, 0x19A4C116, w0, x)
            w1 = uint32(w1 + sigma1(w15) + w10 + sigma0(w2))
            Round(h, a, b, c, d, e, f, g, 0x1E376C08, w1, x)
            w2 = uint32(w2 + sigma1(w0) + w11 + sigma0(w3))
            Round(g, h, a, b, c, d, e, f, 0x2748774C, w2, x)
            w3 = uint32(w3 + sigma1(w1) + w12 + sigma0(w4))
            Round(f, g, h, a, b, c, d, e, 0x34B0BCB5, w3, x)
            w4 = uint32(w4 + sigma1(w2) + w13 + sigma0(w5))
            Round(e, f, g, h, a, b, c, d, 0x391C0CB3, w4, x)
            w5 = uint32(w5 + sigma1(w3) + w14 + sigma0(w6))
            Round(d, e, f, g, h, a, b, c, 0x4ED8AA4A, w5, x)
            w6 = uint32(w6 + sigma1(w4) + w15 + sigma0(w7))
            Round(c, d, e, f, g, h, a, b, 0x5B9CCA4F, w6, x)
            w7 = uint32(w7 + sigma1(w5) + w0 + sigma0(w8))
            Round(b, c, d, e, f, g, h, a, 0x682E6FF3, w7, x)
            w8 = uint32(w8 + sigma1(w6) + w1 + sigma0(w9))
            Round(a, b, c, d, e, f, g, h, 0x748F82EE, w8, x)
            w9 = uint32(w9 + sigma1(w7) + w2 + sigma0(w10))
            Round(h, a, b, c, d, e, f, g, 0x78A5636F, w9, x)
            w10 = uint32(w10 + sigma1(w8) + w3 + sigma0(w11))
            Round(g, h, a, b, c, d, e, f, 0x84C87814, w10, x)
            w11 = uint32(w11 + sigma1(w9) + w4 + sigma0(w12))
            Round(f, g, h, a, b, c, d, e, 0x8CC70208, w11, x)
            w12 = uint32(w12 + sigma1(w10) + w5 + sigma0(w13))
            Round(e, f, g, h, a, b, c, d, 0x90BEFFFA, w12, x)
            w13 = uint32(w13 + sigma1(w11) + w6 + sigma0(w14))
            Round(d, e, f, g, h, a, b, c, 0xA4506CEB, w13, x)
            Round(c, d, e, f, g, h, a, b, 0xBEF9A3F7, w14 + sigma1(w12) + w7 + sigma0(w15), x)
            Round(b, c, d, e, f, g, h, a, 0xC67178F2, w15 + sigma1(w13) + w8 + sigma0(w0), x)

            s[0] = uint32(s[0] + x[a])
            s[1] = uint32(s[1] + x[b])
            s[2] = uint32(s[2] + x[c])
            s[3] = uint32(s[3] + x[d])
            s[4] = uint32(s[4] + x[e])
            s[5] = uint32(s[5] + x[f])
            s[6] = uint32(s[6] + x[g])
            s[7] = uint32(s[7] + x[h])

            chunk = chunk[64:]

    def Write(self: T_CSHA256, data: Union[bytes, bytearray]) -> T_CSHA256:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be instance of bytes or bytearray")

        if self.bytes_count + len(data) > SHA256_MAX:
            raise ValueError("total bytes count beyond max allowed value")

        bufsize = self.bytes_count % 64
        assert len(self.buf) == bufsize
        if bufsize and bufsize + len(data) >= 64:
            # Fill the buffer, and process it.
            remainder_len = 64 - bufsize
            buf = self.buf + data[:remainder_len]
            data = data[remainder_len:]
            self.bytes_count += remainder_len
            self.Transform(buf, 1)
            self.buf = b""
            bufsize = 0

        if len(data) >= 64:
            blocks = len(data) // 64
            self.Transform(data, blocks)
            data = data[64 * blocks :]
            self.bytes_count += 64 * blocks

        if len(data) > 0:
            assert len(data) < 64
            # Fill the buffer with what remains.
            self.buf = self.buf + data
            self.bytes_count += len(data)

        return self

    def Finalize(self) -> bytes:
        pad = b"\x80" + b"\x00" * 63
        sizedesc = struct.pack(b">q", self.bytes_count << 3)
        self.Write(pad[: 1 + ((119 - (self.bytes_count % 64)) % 64)])
        self.Write(sizedesc)
        return self.Midstate()

    def Midstate(self) -> bytes:
        s = self.s

        def ToBE32(x: int) -> bytes:
            return struct.pack(b">I", x)

        hash_chunks = []
        hash_chunks.append(ToBE32(s[0]))
        hash_chunks.append(ToBE32(s[1]))
        hash_chunks.append(ToBE32(s[2]))
        hash_chunks.append(ToBE32(s[3]))
        hash_chunks.append(ToBE32(s[4]))
        hash_chunks.append(ToBE32(s[5]))
        hash_chunks.append(ToBE32(s[6]))
        hash_chunks.append(ToBE32(s[7]))

        return b"".join(hash_chunks)

    def Reset(self) -> "CSHA256":
        self.buf = b""  # type: bytes
        self.bytes_count = 0  # type: int
        self.s = [
            0x6A09E667,
            0xBB67AE85,
            0x3C6EF372,
            0xA54FF53A,
            0x510E527F,
            0x9B05688C,
            0x1F83D9AB,
            0x5BE0CD19,
        ]
        return self


__all__ = ("CSHA256",)
