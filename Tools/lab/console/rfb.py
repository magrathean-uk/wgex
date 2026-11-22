# SPDX-License-Identifier: MIT
"""Minimal RFB (VNC) client for the lab guest's console, standard library only (M03-T07 phase B, DEC-034).

Tart's `--vnc-experimental` serves the guest display through Virtualization.framework's VNC server on 127.0.0.1 with a
one-time password (VNC authentication, security type 2). This client speaks RFB 3.3 to 3.8, answers that challenge with
the protocol's DES variant, asks for raw 32-bit pixels, sends key and pointer events and writes a framebuffer capture as
PNG. It never logs what it types."""
import socket
import struct
import time
import zlib

# DES (FIPS 46-3) tables; VNC authentication encrypts the 16-byte challenge as two ECB blocks with the password as key.
_PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
_PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
_FP = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
       36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
_E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
      16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
_P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)
_S = (
    (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13),
    (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9),
    (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12),
    (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14),
    (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3),
    (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13),
    (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12),
    (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11),
)


def _permute(value, table, bits):
    out = 0
    for position in table:
        out = (out << 1) | ((value >> (bits - position)) & 1)
    return out


def _subkeys(key):
    cd = _permute(int.from_bytes(key, "big"), _PC1, 64)
    c, d = cd >> 28, cd & 0xFFFFFFF
    keys = []
    for shift in _SHIFTS:
        c = ((c << shift) | (c >> (28 - shift))) & 0xFFFFFFF
        d = ((d << shift) | (d >> (28 - shift))) & 0xFFFFFFF
        keys.append(_permute((c << 28) | d, _PC2, 56))
    return keys


def des_encrypt_block(key, block):
    """One DES block (8 bytes) under an 8-byte key."""
    if len(key) != 8 or len(block) != 8:
        raise ValueError("DES works on 8-byte keys and blocks")
    value = _permute(int.from_bytes(block, "big"), _IP, 64)
    left, right = value >> 32, value & 0xFFFFFFFF
    for subkey in _subkeys(key):
        expanded = _permute(right, _E, 32) ^ subkey
        out = 0
        for box in range(8):
            six = (expanded >> (42 - 6 * box)) & 0x3F
            out = (out << 4) | _S[box][(((six & 0x20) >> 4) | (six & 1)) * 16 + ((six >> 1) & 0xF)]
        left, right = right, left ^ _permute(out, _P, 32)
    return _permute((right << 32) | left, _FP, 64).to_bytes(8, "big")


def vnc_auth_response(password, challenge):
    """VNC authentication: the password's first 8 bytes (zero padded), each byte's bits reversed, as the DES key."""
    if len(challenge) != 16:
        raise ValueError("VNC challenge must be 16 bytes")
    raw = password.encode("latin-1")[:8].ljust(8, b"\0")
    key = bytes(int(f"{byte:08b}"[::-1], 2) for byte in raw)
    return des_encrypt_block(key, challenge[:8]) + des_encrypt_block(key, challenge[8:])


# X11 keysyms for the keys the console steps use; printable ASCII maps to its code point.
KEYSYMS = {"Return": 0xFF0D, "Tab": 0xFF09, "Escape": 0xFF1B, "BackSpace": 0xFF08, "Shift": 0xFFE1, "Up": 0xFF52,
           "Down": 0xFF54, "Left": 0xFF51, "Right": 0xFF53, "space": 0x20, "Command": 0xFFE9, "a": 0x61}
# The VNC server turns a keysym into a key position; the guest's input source (British on the lab guest) then picks the
# character. Letters, digits and these punctuation keys sit in the same place, with the same Shift state, on the US and
# British layouts; any other character could come out differently and is refused rather than typed wrong.
LAYOUT_SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 -=[];',./!$%^&*()_+{}:<>?")
SHIFTED = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ!$%^&*()_+{}:<>?")


def keystrokes(text):
    """(keysym, shift) per character; a character whose key differs between the US and British layouts is refused."""
    strokes = []
    for char in text:
        if char not in LAYOUT_SAFE:
            raise ValueError("character outside the layout-safe set")
        strokes.append((ord(char), char in SHIFTED))
    return strokes


class RFBError(RuntimeError):
    pass


class Client:
    """One RFB session. `sock` lets tests hand in one end of a socket pair. With `deadline` (epoch seconds) every blocking
    step (connect, each receive and send) waits at most until then and fails with "deadline passed" afterwards, so a slow
    server cannot carry the session past the caller's typing window."""

    def __init__(self, host, port, password, timeout=30.0, sock=None, key_delay=0.06, deadline=None):
        self.key_delay, self.timeout, self.deadline = key_delay, timeout, deadline
        if sock is None:
            try:
                sock = socket.create_connection((host, port), timeout=self._wait())
            except socket.timeout as error:
                self._wait()
                raise RFBError("VNC connect timed out") from error
        self.sock = sock
        self.width = self.height = 0
        self.framebuffer = bytearray()
        self.name = ""
        self._handshake(password)

    def _wait(self):
        """The socket timeout for the next blocking step; raises once the deadline has passed."""
        if self.deadline is None:
            return self.timeout
        remaining = self.deadline - time.time()
        if remaining <= 0:
            raise RFBError("deadline passed")
        return min(self.timeout, remaining)

    def _send(self, data):
        self.sock.settimeout(self._wait())
        try:
            self.sock.sendall(data)
        except socket.timeout as error:
            self._wait()
            raise RFBError("VNC send timed out") from error

    def _recv(self, count):
        data = bytearray()
        while len(data) < count:
            self.sock.settimeout(self._wait())
            try:
                chunk = self.sock.recv(count - len(data))
            except socket.timeout as error:
                self._wait()
                raise RFBError("VNC receive timed out") from error
            if not chunk:
                raise RFBError("VNC server closed the connection")
            data += chunk
        return bytes(data)

    def _handshake(self, password):
        banner = self._recv(12)
        if not banner.startswith(b"RFB ") or not banner.endswith(b"\n"):
            raise RFBError("not an RFB server")
        major, minor = int(banner[4:7]), int(banner[8:11])
        if major != 3:
            raise RFBError("unsupported RFB major version")
        minor = 8 if minor >= 8 else 7 if minor == 7 else 3
        self._send(b"RFB 003.%03d\n" % minor)
        if minor == 3:
            (chosen,) = struct.unpack(">I", self._recv(4))
            if chosen == 0:
                raise RFBError("VNC server refused the connection")
        else:
            (count,) = struct.unpack(">B", self._recv(1))
            if count == 0:
                raise RFBError("VNC server refused the connection")
            offered = set(self._recv(count))
            chosen = 2 if 2 in offered else 1 if 1 in offered else None
            if chosen is None:
                raise RFBError("VNC server offers no supported security type")
            self._send(bytes([chosen]))
        if chosen == 2:
            self._send(vnc_auth_response(password, self._recv(16)))
        if chosen == 2 or minor == 8:
            (result,) = struct.unpack(">I", self._recv(4))
            if result != 0:
                raise RFBError("VNC authentication failed")
        self._send(b"\x01")  # ClientInit: shared session
        self.width, self.height = struct.unpack(">HH", self._recv(4))
        self._recv(16)
        (length,) = struct.unpack(">I", self._recv(4))
        self.name = self._recv(length).decode(errors="replace")
        # 32 bpp, depth 24, little endian, true colour, 8 bits each: memory order blue, green, red, padding.
        self._send(struct.pack(">B3xBBBBHHHBBB3x", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
        self._send(struct.pack(">BxHii", 2, 2, 0, -223))  # Raw and the DesktopSize pseudo-encoding
        self.framebuffer = bytearray(self.width * self.height * 4)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def key(self, keysym, down):
        self._send(struct.pack(">BBxxI", 4, 1 if down else 0, keysym))

    def tap(self, name_or_keysym, shift=False):
        keysym = KEYSYMS[name_or_keysym] if isinstance(name_or_keysym, str) else name_or_keysym
        if shift:
            self.key(KEYSYMS["Shift"], True)
        self.key(keysym, True)
        time.sleep(self.key_delay / 2)
        self.key(keysym, False)
        if shift:
            self.key(KEYSYMS["Shift"], False)
        time.sleep(self.key_delay)

    def type_text(self, text):
        for keysym, shift in keystrokes(text):
            self.tap(keysym, shift)

    def pointer(self, x, y, buttons=0):
        self._send(struct.pack(">BBHH", 5, buttons, max(0, int(x)), max(0, int(y))))

    def click(self, x, y):
        self.pointer(x, y)
        time.sleep(0.1)
        self.pointer(x, y, 1)
        time.sleep(0.1)
        self.pointer(x, y)
        time.sleep(self.key_delay)

    def refresh(self):
        """A full (non-incremental) framebuffer update; returns (width, height, BGRX bytes)."""
        self._send(struct.pack(">BBHHHH", 3, 0, 0, 0, self.width, self.height))
        while True:
            (kind,) = struct.unpack(">B", self._recv(1))
            if kind == 0:
                self._recv(1)
                (rects,) = struct.unpack(">H", self._recv(2))
                for _ in range(rects):
                    x, y, w, h, encoding = struct.unpack(">HHHHi", self._recv(12))
                    if encoding == -223:
                        self.width, self.height = w, h
                        self.framebuffer = bytearray(w * h * 4)
                        continue
                    if encoding != 0:
                        raise RFBError(f"unexpected encoding {encoding}")
                    data = self._recv(w * h * 4)
                    for row in range(h):
                        start = ((y + row) * self.width + x) * 4
                        self.framebuffer[start:start + w * 4] = data[row * w * 4:(row + 1) * w * 4]
                return self.width, self.height, bytes(self.framebuffer)
            if kind == 1:
                self._recv(3)
                (colours,) = struct.unpack(">H", self._recv(2))
                self._recv(colours * 6)
            elif kind == 2:
                continue
            elif kind == 3:
                self._recv(3)
                (length,) = struct.unpack(">I", self._recv(4))
                self._recv(length)
            else:
                raise RFBError(f"unexpected server message {kind}")


def png_bytes(width, height, bgrx):
    """PNG (8-bit RGB) of a BGRX framebuffer."""
    raw = bytearray()
    for row in range(height):
        line = bgrx[row * width * 4:(row + 1) * width * 4]
        rgb = bytearray(width * 3)
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        raw += b"\0" + rgb

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6)) + chunk(b"IEND", b""))


def region_stats(width, height, bgrx, box):
    """Mean brightness (0..255) and the share of near-white pixels in box (x, y, w, h), sampled every 4th pixel."""
    x0, y0, w, h = box
    total = bright = count = 0
    for y in range(max(0, y0), min(height, y0 + h), 4):
        for x in range(max(0, x0), min(width, x0 + w), 4):
            offset = (y * width + x) * 4
            value = (bgrx[offset] + bgrx[offset + 1] + bgrx[offset + 2]) // 3
            total += value
            bright += value >= 230
            count += 1
    return (total / count, bright / count) if count else (0.0, 0.0)
