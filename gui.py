import threading
import time
import webbrowser

def start_server():
    # import here so the app module doesn't import when not needed
    from webui import app
    app.run(host='127.0.0.1', port=5000, threaded=True)

if __name__ == '__main__':
    t = threading.Thread(target=start_server, daemon=True)
    t.start()
    # give the server a moment
    time.sleep(0.5)
    try:
        import webview
        webview.create_window('file2image', 'http://127.0.0.1:5000')
        webview.start()
    except Exception:
        print('pywebview not installed or failed to start. Opening in default browser instead.')
        webbrowser.open('http://127.0.0.1:5000')
        t.join()