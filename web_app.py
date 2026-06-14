"""Flask entry point for the monitoring dashboard.

Run: python web_app.py  (serves http://127.0.0.1:5000)
This process renders telemetry the agent produces; it does not change any
existing tool or orchestrator logic.
"""

from flask import Flask, render_template

from dashboard_routes import dashboard_bp
from sse_routes import sse_bp


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.register_blueprint(sse_bp)
    app.register_blueprint(dashboard_bp)

    @app.route("/")
    def index():
        return render_template("index.html")

    return app


app = create_app()


if __name__ == "__main__":
    # threaded=True is required: the SSE endpoint holds a worker for the life of
    # each browser tab, so without threading the control POSTs would block.
    # Single-user local tool, so the dev server is sufficient and debug stays off.
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=False)
