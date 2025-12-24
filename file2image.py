#!/usr/bin/env python3
# file2image.py
"""
Batch file <-> PNG encoder (streaming, compressed, optional encryption)

Folders (project root):
  ./to_encode        # inputs to encode
  ./encoded          # outputs (PNGs)
  ./recovered_files  # decoded outputs

Usage:
  # encode all files found in ./to_encode -> ./encoded
  python file2image.py encode [--compress {none,zlib,lzma}] [--encrypt] [--width WIDTH] [--iters N]

  # decode all PNGs found in ./encoded -> ./recovered_files
  python file2image.py decode
"""
import argparse
import base64
import getpass
import json
import math
import os
import secrets
import struct
import sys
import tempfile
import zlib
import lzma
import zipfile
try:
    import zstandard as zstd
except Exception:
    zstd = None  # optional dependency
from pathlib import Path

import png  # pypng
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Constants
MAGIC = "FILE2IMAGE_v1"
DEFAULT_PBKDF2_ITERS = 200_000
PBKDF2_SALT_BYTES = 16
GCM_NONCE_BYTES = 12
AES_KEY_BYTES = 32  # AES-256
CHUNK = 64 * 1024

# Verbose debug gate (set via --verbose / -v)
VERBOSE = False

from collections import deque
LOGS = deque(maxlen=1000)

def debug(msg):
    if VERBOSE:
        s = "[debug] " + str(msg)
        LOGS.append(s)
        print(s)

def log(msg):
    s = str(msg)
    LOGS.append(s)
    print(s)

# Default folders (relative to script cwd)
# Use a top-level `files/` folder that contains `to_encode`, `encoded`, `recovered_files` subfolders
TO_ENCODE = Path("files") / "to_encode"
ENCODED_DIR = Path("files") / "encoded"
RECOVERED_DIR = Path("files") / "recovered_files"


def ensure_dirs():
    TO_ENCODE.mkdir(parents=True, exist_ok=True)
    ENCODED_DIR.mkdir(parents=True, exist_ok=True)
    RECOVERED_DIR.mkdir(parents=True, exist_ok=True)


def derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=AES_KEY_BYTES, salt=salt, iterations=iterations
    )
    return kdf.derive(password)


def stream_compress_file(in_path: Path, compressor_name: str, out_path: Path):
    if compressor_name == "none":
        with in_path.open("rb") as r, out_path.open("wb") as w:
            while True:
                b = r.read(CHUNK)
                if not b:
                    break
                w.write(b)
    elif compressor_name == "zlib":
        comp = zlib.compressobj(level=9)
        with in_path.open("rb") as r, out_path.open("wb") as w:
            while True:
                b = r.read(CHUNK)
                if not b:
                    break
                w.write(comp.compress(b))
            w.write(comp.flush())
    elif compressor_name == "lzma":
        comp = lzma.LZMACompressor(format=lzma.FORMAT_XZ)
        with in_path.open("rb") as r, out_path.open("wb") as w:
            while True:
                b = r.read(CHUNK)
                if not b:
                    break
                w.write(comp.compress(b))
            w.write(comp.flush())
    elif compressor_name == "zstd":
        if zstd is None:
            raise ValueError("zstandard not installed; install with 'pip install zstandard'")
        cctx = zstd.ZstdCompressor()
        with in_path.open("rb") as r, out_path.open("wb") as w:
            with cctx.stream_writer(w) as compressor:
                while True:
                    b = r.read(CHUNK)
                    if not b:
                        break
                    compressor.write(b)
    else:
        raise ValueError("Unknown compressor: " + compressor_name)
    return out_path.stat().st_size


def stream_encrypt_file(in_path: Path, key: bytes, nonce: bytes, out_path: Path):
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, modes.GCM(nonce))
    encryptor = cipher.encryptor()
    with in_path.open("rb") as r, out_path.open("wb") as w:
        while True:
            chunk = r.read(CHUNK)
            if not chunk:
                break
            ct = encryptor.update(chunk)
            if ct:
                w.write(ct)
        final = encryptor.finalize()
        if final:
            w.write(final)
        tag = encryptor.tag
    return tag


def write_png_from_stream(stream, total_payload_len: int, out_png_path: Path, force_width=0):
    num_pixels = math.ceil(total_payload_len / 3)
    width = int(force_width) if force_width and force_width > 0 else math.ceil(math.sqrt(num_pixels))
    height = math.ceil(num_pixels / width)
    row_bytes = width * 3
    writer = png.Writer(width, height, greyscale=False, alpha=False, bitdepth=8)

    with out_png_path.open("wb") as fout:
        def rows():
            remaining = total_payload_len
            while remaining > 0:
                to_read = min(row_bytes, remaining)
                chunk = stream.read(to_read)
                pre_pad_len = len(chunk) if chunk else 0
                if not chunk:
                    chunk = b""
                if len(chunk) < row_bytes:
                    chunk += b"\x00" * (row_bytes - len(chunk))
                # Subtract the actual number of payload bytes consumed (before padding)
                remaining -= pre_pad_len
                yield chunk
            rows_emitted = math.ceil(math.ceil(total_payload_len / 3) / width)
            for _ in range(rows_emitted, height):
                yield b"\x00" * row_bytes

        writer.write(fout, rows())
    return width, height


def compute_meta_and_padding(meta_obj, ciphertext_len, tag_len):
    while True:
        meta_json = json.dumps(meta_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        meta_len = len(meta_json)
        combined_len = 4 + meta_len + ciphertext_len + tag_len
        padding = (3 - (combined_len % 3)) % 3
        if meta_obj.get("padding") == padding and meta_obj.get("meta_len") == meta_len:
            return meta_json, meta_len, padding
        meta_obj["padding"] = padding
        meta_obj["meta_len"] = meta_len


class FileCombinedStream:
    def __init__(self, meta_json: bytes, meta_len: int, ciphertext_path: Path, tag_path: Path, tag_bytes: bytes = None, padding: int = 0):
        self.header = struct.pack(">I", meta_len) + meta_json
        self.header_pos = 0
        self.ct_path = ciphertext_path
        self.ct_file = None
        # tag can be provided either as a Path (on-disk) or as in-memory bytes
        self.tag_path = tag_path
        self.tag_file = None
        self.tag_bytes = tag_bytes
        self.tag_len = 0
        if self.tag_bytes is not None:
            self.tag_len = len(self.tag_bytes)
        elif self.tag_path is not None:
            self.tag_len = self.tag_path.stat().st_size
        self.tag_pos = 0
        self.padding = padding
        self.phase = 0

    def read(self, n):
        if n <= 0:
            return b""
        out = bytearray()
        while len(out) < n:
            if self.phase == 0:
                remain = len(self.header) - self.header_pos
                if remain <= 0:
                    self.phase = 1
                    continue
                take = min(n - len(out), remain)
                out += self.header[self.header_pos : self.header_pos + take]
                self.header_pos += take
            elif self.phase == 1:
                if self.ct_file is None:
                    self.ct_file = self.ct_path.open("rb")
                chunk = self.ct_file.read(n - len(out))
                if not chunk:
                    self.ct_file.close()
                    self.ct_file = None
                    self.phase = 2
                    continue
                out += chunk
            elif self.phase == 2:
                # Serve tag bytes from in-memory buffer if available
                if self.tag_bytes is not None:
                    if self.tag_pos >= self.tag_len:
                        self.phase = 3
                        continue
                    take = min(n - len(out), self.tag_len - self.tag_pos)
                    out += self.tag_bytes[self.tag_pos : self.tag_pos + take]
                    self.tag_pos += take
                    if self.tag_pos >= self.tag_len:
                        self.phase = 3
                        continue
                else:
                    # Fallback to reading the tag file from disk
                    if self.tag_path is None:
                        self.phase = 3
                        continue
                    if self.tag_file is None:
                        self.tag_file = self.tag_path.open("rb")
                    toread = n - len(out)
                    chunk = self.tag_file.read(toread)
                    if chunk is not None:
                        if hasattr(self, '_tag_debug_printed') is False:
                            try:
                                debug(f"FileCombinedStream: read tag chunk (hex): {chunk.hex()}")
                            except Exception:
                                debug("FileCombinedStream: read tag chunk (non-hex)")
                            self._tag_debug_printed = True
                    if not chunk:
                        self.tag_file.close()
                        self.tag_file = None
                        self.phase = 3
                        continue
                    out += chunk
            elif self.phase == 3:
                if self.padding <= 0:
                    return bytes(out)
                take = min(n - len(out), self.padding)
                out += b"\x00" * take
                self.padding -= take
                if self.padding <= 0:
                    return bytes(out)
            else:
                return bytes(out)
        return bytes(out)


def encode_file(path: Path, args):
    log(f"[encode] {path.name}")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        compressed = td / "payload.compressed"
        compressed_size = stream_compress_file(path, args.compress, compressed)

        # If compression does not reduce size, store raw file (avoid expanding compressed artifacts)
        used_compressor = args.compress
        if args.compress != "none" and compressed_size >= path.stat().st_size:
            print("  -> compression not effective; using uncompressed file")
            compressed = path
            used_compressor = "none"

        ciphertext = compressed
        tag_path = None
        salt_b64 = None
        nonce_b64 = None

        if args.encrypt:
            password = os.environ.get("FILE2IMAGE_PASSWORD")
            if not password:
                password = getpass.getpass("Password for encryption: ")
            pwb = password.encode("utf-8")
            salt = secrets.token_bytes(PBKDF2_SALT_BYTES)
            key = derive_key(pwb, salt, args.iters)
            nonce = secrets.token_bytes(GCM_NONCE_BYTES)
            encrypted = td / "payload.encrypted"
            tag = stream_encrypt_file(compressed, key, nonce, encrypted)
            tag_path = td / "payload.tag"
            tag_path.write_bytes(tag)
            # Debug: verify tag bytes were written correctly (should not be all zeros)
            try:
                tag_file_bytes = tag_path.read_bytes()
                if tag_file_bytes != tag:
                    debug("WARNING: tag bytes mismatch between in-memory tag and written file")
                if all(b == 0 for b in tag_file_bytes):
                    debug("WARNING: tag bytes are all zeros — this will cause decryption to fail")
                else:
                    debug(f"tag (hex): {tag_file_bytes.hex()}")
            except Exception as _:
                debug("could not read back tag file for verification")
            ciphertext = encrypted
            salt_b64 = base64.b64encode(salt).decode("ascii")
            nonce_b64 = base64.b64encode(nonce).decode("ascii")

        ciphertext_len = ciphertext.stat().st_size
        tag_len = 0 if tag_path is None else tag_path.stat().st_size

        metadata = {
            "magic": MAGIC,
            "version": 1,
            "filename": path.name,
            "original_size": path.stat().st_size,
            "compressor": used_compressor,
            "encrypted": bool(args.encrypt),
            "kdf": {
                "name": "pbkdf2",
                "salt_b64": salt_b64,
                "iterations": args.iters if args.encrypt else None,
            },
            "gcm": {"nonce_b64": nonce_b64, "tag_len": tag_len},
        }

        meta_json, meta_len, padding = compute_meta_and_padding(metadata, ciphertext_len, tag_len)
        total_payload_len = 4 + meta_len + ciphertext_len + tag_len + padding

        # Debug: print ciphertext size and tag bytes immediately before writing PNG
        try:
            debug(f"ciphertext size: {ciphertext.stat().st_size} bytes")
            if tag_path is not None and tag_path.exists():
                tb = tag_path.read_bytes()
                debug(f"tag before writing PNG (hex): {tb.hex()}")
        except Exception:
            debug("could not stat/read ciphertext/tag files")

        # Debug: also write the raw combined payload to a temp file for comparison
        try:
            # Persist raw payload to a stable location for comparison
            os.makedirs('tmp', exist_ok=True)
            raw_payload = Path('tmp/payload.raw')
            s = FileCombinedStream(meta_json, meta_len, ciphertext, tag_path, tag_bytes=(tag if 'tag' in locals() else None), padding=padding)
            toread = total_payload_len
            with raw_payload.open("wb") as rf:
                while toread > 0:
                    chunk = s.read(min(CHUNK, toread))
                    if not chunk:
                        break
                    rf.write(chunk)
                    toread -= len(chunk)
            rb = raw_payload.read_bytes()
            debug(f"last 64 bytes of raw payload (hex): {rb[-64:].hex()}")
        except Exception:
            debug("could not write/read raw payload file")

        combined = FileCombinedStream(meta_json, meta_len, ciphertext, tag_path, tag_bytes=(tag if 'tag' in locals() else None), padding=padding)
        out_png = ENCODED_DIR / (path.name + ".png")
        log(f"  -> writing PNG (payload {total_payload_len} bytes)...")
        width, height = write_png_from_stream(combined, total_payload_len, out_png, force_width=args.width)
        log(f"  -> {out_png.name} ({width}x{height})")


def decode_file(png_path: Path, args):
    log(f"[decode] {png_path.name}")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        reader = png.Reader(filename=str(png_path))
        width, height, rows, info = reader.read()
        raw_path = td / "png_raw.bin"
        with raw_path.open("wb") as rawf:
            for row in rows:
                if isinstance(row, (bytes, bytearray)):
                    rawf.write(row)
                else:
                    rawf.write(bytes(row))
        with raw_path.open("rb") as rawf:
            header4 = rawf.read(4)
            if len(header4) < 4:
                log("  - payload too short")
                return
            meta_len = struct.unpack(">I", header4)[0]
            meta_json = rawf.read(meta_len)
            metadata = json.loads(meta_json.decode("utf-8"))
            padding = int(metadata.get("padding", 0))
            tag_len = int(metadata.get("gcm", {}).get("tag_len", 0))
            encrypted = bool(metadata.get("encrypted", False))
            compressor = metadata.get("compressor", "none")
            filename = metadata.get("filename", "output.bin")

            # Read the entire remaining payload into memory and account for
            # any extra zero-padding added to fill the final PNG rows.
            payload_bytes = rawf.read()
            remaining_total = len(payload_bytes)

            # Count trailing zeros (these include the original padding plus extra row padding)
            trailing_zeros = len(payload_bytes) - len(payload_bytes.rstrip(b"\x00"))
            extra_row_padding = max(0, trailing_zeros - padding)

            ciphertext_len = remaining_total - tag_len - padding - extra_row_padding
            if ciphertext_len < 0:
                raise ValueError("Payload too short or corrupted (computed negative ciphertext length)")

            ciphertext_path = td / "payload.cipher"
            ciphertext_path.write_bytes(payload_bytes[:ciphertext_len])

            if tag_len:
                tag_bytes = payload_bytes[ciphertext_len : ciphertext_len + tag_len]
            else:
                tag_bytes = None

            if encrypted:
                password = os.environ.get("FILE2IMAGE_PASSWORD")
                if not password:
                    password = getpass.getpass("Password for decryption: ")
                pwb = password.encode("utf-8")
                salt_b64 = metadata.get("kdf", {}).get("salt_b64")
                salt = base64.b64decode(salt_b64) if salt_b64 else None
                iters = int(metadata.get("kdf", {}).get("iterations", DEFAULT_PBKDF2_ITERS))
                key = derive_key(pwb, salt, iters)
                nonce_b64 = metadata.get("gcm", {}).get("nonce_b64")
                nonce = base64.b64decode(nonce_b64)
                dec_out = td / "payload.decrypted"
                algorithm = algorithms.AES(key)
                cipher = Cipher(algorithm, modes.GCM(nonce, tag_bytes))
                decryptor = cipher.decryptor()
                with ciphertext_path.open("rb") as cf, dec_out.open("wb") as df:
                    while True:
                        chunk = cf.read(CHUNK)
                        if not chunk:
                            break
                        pt = decryptor.update(chunk)
                        if pt:
                            df.write(pt)
                    try:
                        final = decryptor.finalize()
                        if final:
                            df.write(final)
                    except Exception as e:
                        raise ValueError("Decryption failed or authentication tag mismatch.") from e
                compressed_path = dec_out
            else:
                compressed_path = ciphertext_path

            decompressed_path = td / "payload.decompressed"
            if compressor == "none":
                with compressed_path.open("rb") as r, decompressed_path.open("wb") as w:
                    while True:
                        b = r.read(CHUNK)
                        if not b:
                            break
                        w.write(b)
            elif compressor == "zlib":
                decomp = zlib.decompressobj()
                with compressed_path.open("rb") as r, decompressed_path.open("wb") as w:
                    while True:
                        b = r.read(CHUNK)
                        if not b:
                            break
                        w.write(decomp.decompress(b))
                    w.write(decomp.flush())
            elif compressor == "lzma":
                decomp = lzma.LZMADecompressor(format=lzma.FORMAT_XZ)
                with compressed_path.open("rb") as r, decompressed_path.open("wb") as w:
                    while True:
                        b = r.read(CHUNK)
                        if not b:
                            break
                        w.write(decomp.decompress(b))
            elif compressor == "zstd":
                if zstd is None:
                    raise ValueError("zstandard not installed; install with 'pip install zstandard'")
                dctx = zstd.ZstdDecompressor()
                with compressed_path.open("rb") as r, decompressed_path.open("wb") as w:
                    with dctx.stream_reader(r) as reader:
                        while True:
                            b = reader.read(CHUNK)
                            if not b:
                                break
                            w.write(b)
            else:
                raise ValueError("Unknown compressor: " + str(compressor))

            out_path = RECOVERED_DIR / filename
            if out_path.exists():
                base = out_path.stem
                suf = out_path.suffix
                i = 1
                while True:
                    cand = RECOVERED_DIR / f"{base}_{i}{suf}"
                    if not cand.exists():
                        out_path = cand
                        break
                    i += 1
            with decompressed_path.open("rb") as r, out_path.open("wb") as w:
                while True:
                    b = r.read(CHUNK)
                    if not b:
                        break
                    w.write(b)
            log(f"  -> recovered: {out_path.name}")


from concurrent.futures import ProcessPoolExecutor, as_completed


def _encode_helper(path_str, args_dict):
    # Worker helper executed in subprocess
    from argparse import Namespace
    args_ns = Namespace(**args_dict)
    global VERBOSE
    VERBOSE = bool(getattr(args_ns, "verbose", False))
    try:
        encode_file(Path(path_str), args_ns)
        return (path_str, None)
    except Exception as e:
        return (path_str, str(e))


def encode_batch(args):
    ensure_dirs()
    files = [p for p in TO_ENCODE.iterdir() if p.is_file() and not p.name.startswith(".")]
    if not files:
        log("No files found in 'to_encode'. Place files there and run encode.")
        return

    workers = args.workers if getattr(args, "workers", 0) > 0 else max(1, (os.cpu_count() or 1) * 2)
    if len(files) == 1 or workers == 1:
        for f in files:
            try:
                encode_file(f, args)
            except Exception as e:
                log(f"Error encoding {f.name}: {e}")
        return

    # Parallel encoding using processes
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_encode_helper, str(f), vars(args)): f for f in files}
        for fut in as_completed(futures):
            path, err = fut.result()
            if err:
                log(f"Error encoding {Path(path).name}: {err}")
            else:
                log(f"Encoded: {Path(path).name}")


def _decode_helper(path_str, args_dict):
    from argparse import Namespace
    args_ns = Namespace(**args_dict)
    global VERBOSE
    VERBOSE = bool(getattr(args_ns, "verbose", False))
    try:
        decode_file(Path(path_str), args_ns)
        return (path_str, None)
    except Exception as e:
        return (path_str, str(e))


def decode_batch(args):
    ensure_dirs()
    pngs = [p for p in ENCODED_DIR.iterdir() if p.is_file() and p.suffix.lower() == ".png"]
    if not pngs:
        log("No PNGs found in 'encoded' to decode.")
        return

    workers = args.workers if getattr(args, "workers", 0) > 0 else max(1, (os.cpu_count() or 1) * 2)
    if len(pngs) == 1 or workers == 1:
        for p in pngs:
            try:
                decode_file(p, args)
            except Exception as e:
                log(f"Error decoding {p.name}: {e}")
        return

    from concurrent.futures import ProcessPoolExecutor, as_completed
    with ProcessPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_decode_helper, str(p), vars(args)): p for p in pngs}
        for fut in as_completed(futures):
            path, err = fut.result()
            if err:
                log(f"Error decoding {Path(path).name}: {err}")
            else:
                log(f"Decoded: {Path(path).name}")


def main():
    parser = argparse.ArgumentParser(description="Batch file <-> PNG encoder (streaming, compressed, optional encryption)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose debug output")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encode", help="Encode all files from ./to_encode -> ./encoded")
    # Allow --compress to be passed as a flag (defaults to 'lzma') or with an explicit value:
    #   --compress         -> use lzma
    #   --compress zlib    -> use zlib
    #   --compress none    -> disable compression
    default_compressor = 'zstd' if zstd is not None else 'lzma'
    enc.add_argument("--compress", nargs='?', const='zstd', choices=["none", "zlib", "lzma", "zstd"], default=default_compressor,
                     help="Enable compression. If provided without a value, defaults to zstd if installed, otherwise 'lzma'. To disable, use '--compress none'.")
    enc.add_argument("--workers", type=int, default=0, help="Number of parallel workers (0=auto)")
    enc.add_argument("--encrypt", action="store_true", help="Enable AES-GCM encryption (password via FILE2IMAGE_PASSWORD or prompt)")
    enc.add_argument("--width", type=int, default=0, help="Force PNG width (pixels)")
    enc.add_argument("--iters", type=int, default=DEFAULT_PBKDF2_ITERS, help="PBKDF2 iterations")

    dec = sub.add_parser("decode", help="Decode all PNGs from ./encoded -> ./recovered_files")
    dec.add_argument("--workers", type=int, default=0, help="Number of parallel workers (0=auto)")

    args = parser.parse_args()
    # enable module-level debug gate
    global VERBOSE
    VERBOSE = bool(getattr(args, "verbose", False))
    if args.cmd == "encode":
        encode_batch(args)
    elif args.cmd == "decode":
        decode_batch(args)


if __name__ == "__main__":
    main()
