# file2image 🗂️➡️🖼️

**file2image** is a small command-line tool to encode arbitrary files into PNG images (streaming, compressed) and decode them back. It supports optional AES-GCM encryption and multiple compression modes. The tool is designed for batch operation using a `files/` folder with these subfolders:

- `files/to_encode/` — place files you want encoded here
- `files/encoded/` — PNG outputs will be written here
- `files/recovered_files/` — decoded files will be written here

(If you previously used top-level `to_encode/`, `encoded/`, `recovered_files/`, you can move those folders into `files/`.)

---

## Features ✅

- Encode arbitrary files into PNG images (payload stored in RGB pixels)
- Decode PNGs back into original files
- Streaming compression options: **none**, **zlib**, **lzma**, **zstd** (default: zstd)
- Optional AES-GCM encryption (password prompt or `FILE2IMAGE_PASSWORD` env var)
- Safe metadata header with filename, original size, compressor, and KDF/gcm parameters

---

## Requirements 🔧

- Python 3.8+
- See `requirements.txt` (includes `pypng`, `cryptography`). Optional GUI components require `flask` and `pywebview`. Zstandard (`zstandard`) is optional but recommended for best compression.

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

If you prefer only the command-line features, the core requirements are sufficient; otherwise install all packages from `requirements.txt` to enable the GUI and `zstd` support.

---

## Usage 🧭

Basic commands (run from project root):

- Encode all files in `to_encode/` → PNGs to `encoded/`:

```bash
python file2image.py encode [--compress {none,zlib,lzma,zstd}] [--encrypt] [--width WIDTH] [--iters N] [--workers N]
```

- Decode all PNGs in `encoded/` → files to `recovered_files/`:

```bash
python file2image.py decode
```

### Examples

- Encode with defaults (lzma compression):

```bash
python file2image.py encode
```

- Encode with zlib compression and a forced PNG width of 1024 pixels:

```bash
python file2image.py encode --compress zlib --width 1024
```

- Encode with encryption (you will be prompted for a password):

```bash
python file2image.py encode --encrypt
```

Alternatively set a password in the environment to avoid the prompt:

```bash
export FILE2IMAGE_PASSWORD="s3cret"
python file2image.py encode --encrypt
```

- Decode (will prompt for password when needed):

```bash
python file2image.py decode
```

---

## How it works (brief) 💡

- Files are streamed and compressed (optional) into a temporary payload
- If encryption is enabled, the payload is encrypted with AES-GCM and a PBKDF2-derived key
- A compact JSON metadata header (filename, sizes, compressor, KDF/GCM data) is prepended
- The combined header + payload is padded to align to 3 bytes, then written into PNG pixels (RGB triples)
- Decoding reverses the process and restores the original file into `recovered_files/`

---

## Security notes ⚠️

- Encryption uses AES-GCM with a PBKDF2 key derived from your password (default iterations: 200000). You can customize iterations with `--iters`.
- Keep your password secret. If you lose it, encrypted files cannot be recovered.
- The script stores KDF salt and GCM nonce in the metadata (necessary for decryption).

> **Note:** This tool is designed for convenience and experimentation. Do not rely on it as a secure archival solution for highly sensitive data without reviewing and auditing the implementation.

---

## Contributing 🤝

- Bug reports, improvements, and PRs are welcome.
- Add tests for edge cases (very large files, corrupt PNGs, invalid tags) if you make changes.

---

## License 📄

No license is included in this repository by default. If you want to assign a license, add a `LICENSE` file (e.g., MIT, Apache-2.0) and update this README.

---

## Acknowledgements

- Uses `pypng` for PNG writing/reading
- Uses `cryptography` for AES-GCM and PBKDF2

---

If you'd like edits (more examples, badges, or a specific license), tell me what to include and I'll update `README.md`.

---

## GUI and parallel processing 🚀

- Start the local web GUI: install dependencies, then run `python webui.py` and open http://127.0.0.1:5000 (or `python gui.py` to open in a native window if `pywebview` is installed).
- If `Flask` or other GUI deps are missing, `webui.py` will print a helpful message explaining how to install them.
- The GUI lets you pick compression (`zstd` recommended), enable encryption, and set the number of worker processes for parallel encode/decode.
- CLI: you can also pass `--workers N` to `encode` or `decode` to run with N parallel workers (0 = auto, defaults to cores x2).

Quick setup example:

```bash
# install everything needed for GUI + zstd
python -m pip install -r requirements.txt
# start the web UI
python webui.py
# or open a native window (if pywebview installed)
python gui.py
```

---
