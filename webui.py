from threading import Thread
import time
import os
from pathlib import Path
import sys
from werkzeug.utils import secure_filename

# Import Flask lazily with a helpful message if missing
try:
    from flask import Flask, request, jsonify, send_from_directory
except Exception:
    print("Flask is not installed. To use the GUI, install requirements: python -m pip install -r requirements.txt")
    sys.exit(1)

app = Flask(__name__, static_folder='static')

# Background task state
TASK = {'running': False, 'type': None}

# Helper: list files in the project's files/ subfolders
def list_files():
    from file2image import TO_ENCODE, ENCODED_DIR, RECOVERED_DIR
    def entries(p):
        p = Path(p)
        out = []
        if p.exists():
            for f in sorted(p.iterdir()):
                if f.is_file():
                    out.append({'name': f.name, 'size': f.stat().st_size, 'mtime': f.stat().st_mtime})
        return out
    return {'to_encode': entries(TO_ENCODE), 'encoded': entries(ENCODED_DIR), 'recovered_files': entries(RECOVERED_DIR)}

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/encode', methods=['POST'])
def api_encode():
    if TASK['running']:
        return jsonify({'ok': False, 'error': 'Task already running'}), 400
    data = request.json or {}
    # Build args namespace
    from argparse import Namespace
    args = Namespace()
    args.compress = data.get('compress', 'zstd')
    args.encrypt = bool(data.get('encrypt', False))
    args.width = int(data.get('width', 0))
    args.iters = int(data.get('iters', 200000))
    args.workers = int(data.get('workers', 0))
    args.verbose = bool(data.get('verbose', False))
    password = data.get('password')
    if password:
        os.environ['FILE2IMAGE_PASSWORD'] = password

    def run_task():
        try:
            TASK['running'] = True
            TASK['type'] = 'encode'
            from file2image import encode_batch
            encode_batch(args)
        finally:
            TASK['running'] = False
            TASK['type'] = None

    Thread(target=run_task, daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/list')
def api_list():
    return jsonify({'ok': True, 'files': list_files()})


@app.route('/api/upload', methods=['POST'])
def api_upload():
    if 'file' not in request.files:
        return jsonify({'ok': False, 'error': 'no file part'}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({'ok': False, 'error': 'no selected file'}), 400
    filename = secure_filename(f.filename)
    from file2image import TO_ENCODE
    TO_ENCODE.mkdir(parents=True, exist_ok=True)
    dest = Path(TO_ENCODE) / filename
    f.save(str(dest))
    return jsonify({'ok': True, 'filename': filename})


@app.route('/api/encode-file', methods=['POST'])
def api_encode_file():
    data = request.json or {}
    filename = data.get('filename')
    if not filename:
        return jsonify({'ok': False, 'error': 'filename required'}), 400
    from argparse import Namespace
    args = Namespace()
    args.compress = data.get('compress', 'zstd')
    args.encrypt = bool(data.get('encrypt', False))
    args.width = int(data.get('width', 0))
    args.iters = int(data.get('iters', 200000))
    args.verbose = bool(data.get('verbose', False))
    password = data.get('password')
    if password:
        os.environ['FILE2IMAGE_PASSWORD'] = password

    def run_task():
        try:
            TASK['running'] = True
            TASK['type'] = f'encode:{filename}'
            from file2image import encode_file
            from file2image import TO_ENCODE
            fp = Path(TO_ENCODE) / filename
            if not fp.exists():
                raise FileNotFoundError(str(fp))
            encode_file(fp, args)
        finally:
            TASK['running'] = False
            TASK['type'] = None

    Thread(target=run_task, daemon=True).start()
    return jsonify({'ok': True})


@app.route('/api/decode-file', methods=['POST'])
def api_decode_file():
    data = request.json or {}
    filename = data.get('filename')
    if not filename:
        return jsonify({'ok': False, 'error': 'filename required'}), 400
    from argparse import Namespace
    args = Namespace()
    args.verbose = bool(data.get('verbose', False))

    def run_task():
        try:
            TASK['running'] = True
            TASK['type'] = f'decode:{filename}'
            from file2image import decode_file
            from file2image import ENCODED_DIR
            fp = Path(ENCODED_DIR) / filename
            if not fp.exists():
                raise FileNotFoundError(str(fp))
            decode_file(fp, args)
        finally:
            TASK['running'] = False
            TASK['type'] = None

    Thread(target=run_task, daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/decode', methods=['POST'])
def api_decode():
    if TASK['running']:
        return jsonify({'ok': False, 'error': 'Task already running'}), 400
    data = request.json or {}
    from argparse import Namespace
    args = Namespace()
    args.workers = int(data.get('workers', 0))
    args.verbose = bool(data.get('verbose', False))

    def run_task():
        try:
            TASK['running'] = True
            TASK['type'] = 'decode'
            from file2image import decode_batch
            decode_batch(args)
        finally:
            TASK['running'] = False
            TASK['type'] = None

    Thread(target=run_task, daemon=True).start()
    return jsonify({'ok': True})

@app.route('/api/logs')
def api_logs():
    from file2image import LOGS
    # return last 200 logs
    return jsonify({'running': TASK['running'], 'type': TASK['type'], 'logs': list(LOGS)[-200:]})

@app.route('/static/<path:p>')
def static_files(p):
    return send_from_directory('static', p)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
