from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=["POST"])
def handle_post():
    print("\nReceived form fields:")
    for key in request.form:
        print(f"{key}: {request.form.getlist(key)}")

    print("\nReceived files:")
    for key in request.files:
        file = request.files[key]
        print(f"{key}: filename={file.filename}, content_type={file.content_type}")
        content = file.read()
        print(f"  size={len(content)} bytes")

    return "OK", 200


if __name__ == "__main__":
    from gunicorn.app.base import BaseApplication

    class StandaloneApplication(BaseApplication):
        def __init__(self, app, options=None):
            self.options = options or {}
            self.application = app
            super().__init__()

        def load_config(self):
            config = {key: value for key, value in self.options.items()
                      if key in self.cfg.settings and value is not None}
            for key, value in config.items():
                self.cfg.set(key.lower(), value)

        def load(self):
            return self.application

    options = {
        "bind": "0.0.0.0:8080",
        "workers": 2,
        "worker_class": "gthread",
        "keepalive": 10,
    }

    StandaloneApplication(app, options).run()