import json
import requests
import sys

from flask import Flask, jsonify, request
from threading import Thread
from uuid import uuid4


class MockServer(Thread):
    def __init__(self, port=1234):
        super().__init__()
        self.port = port
        self.app = Flask(__name__)
        self.app.config['TESTING'] = True
        self.url = "http://0.0.0.0:%s" % self.port
        self.known_images = dict()
        self.report_result = "unknown"
        self.return_error_500 = 0

        self.app.add_url_rule("/shutdown", view_func=self._shutdown_server)
        self.add_json_response("/api/scanning/v1/anchore/images", [])
        self.add_json_response("/api/scanning/v1/anchore/status", dict())
        self.add_json_response("/api/scanning/v1/account", dict(name="tenant_fake"))
        self.add_json_response("/api/scanning/v1/anchore/account", dict(name="tenant_fake"))
        self.add_callback_response(
            "/api/scanning/v1/sync/import/images",
            self.handle_import,
            methods=('POST',))
        self.add_callback_response(
            "/api/scanning/v1/import/images",
            self.handle_import,
            methods=('POST',))
        self.add_callback_response(
            "/api/scanning/v1/anchore/images/<digest>/check",
            self.handle_images)
        self.add_callback_response(
            "/api/scanning/v1/anchore/images/<digest>",
            self.handle_image_delete,
            methods=('DELETE',))
        self.add_callback_response(
            "/<path:path>",
            self.catch_all,
            methods=('GET', 'POST', 'DELETE'))

    def _shutdown_server(self):
        if 'werkzeug.server.shutdown' not in request.environ:
            raise RuntimeError('Not running the development server')
        request.environ['werkzeug.server.shutdown']()
        return 'Server shutting down...'

    def shutdown_server(self):
        requests.get("http://localhost:%s/shutdown" % self.port)
        self.join()

    def add_callback_response(self, url, callback, methods=('GET',)):
        self.app.add_url_rule(url, view_func=callback, methods=methods)

    def add_json_response(self, url, serializable, methods=('GET',)):
        def callback():
            return jsonify(serializable)
        callback.__name__ = str(uuid4())  # change name of method to mitigate flask exception

        self.add_callback_response(url, callback, methods=methods)

    def run(self):
        self.app.run(port=self.port)

    def handle_import(self):
        self.known_images[request.headers["digestId"]] = None
        request.files['archive_file'].read()
        return dict(code=0, message="OK", detail=dict())

    def handle_images(self, digest):
        if self.return_error_500 > 0:
            self.return_error_500 = self.return_error_500 - 1
            return (dict(), 500)
        if digest in self.known_images:
            tag = request.args.get('tag')
            report = self.known_images[digest]
            if report == None:
                report = [{
                    digest: {
                        tag: [{
                            "status": self.report_result,
                            "last_evaluation": "2020-10-29T17:18:50Z",
                            "detail": {
                                "result": {
                                    "final_action": "warn",
                                    "image_id": "imageid-xxxx",
                                    "result": {
                                        "imageid-xxxx": {
                                            "result": {
                                                "final_action": "warn",
                                                "image_id": "imageid-xxxx",
                                                "header": [
                                                    "Image_Id",
                                                    "Repo_Tag",
                                                    "Trigger_Id",
                                                    "Gate",
                                                    "Trigger",
                                                    "Check_Output",
                                                    "Gate_Action",
                                                    "Whitelisted",
                                                    "Policy_Id"
                                                ],
                                                "rows": [
                                                    [
                                                        "imageid-xxxx",
                                                        tag,
                                                        "41cb7cdf04850e33a11f80c42bf660b3",
                                                        "mock-gate",
                                                        "mock-trigger",
                                                        "Gate output 1",
                                                        "warn",
                                                        False,
                                                        "default"
                                                    ],
                                                    [
                                                        "imageid-xxxx",
                                                        tag,
                                                        "1571e70ee221127984dcf585a56d4cff",
                                                        "mock-gate",
                                                        "mock-trigger",
                                                        "Gate output 2",
                                                        "warn",
                                                        False,
                                                        "default"
                                                    ]
                                                ]
                                            }
                                        }
                                    }
                                }
                            }
                        }]
                    }
                }]
            return (json.dumps(report), 200)
        else:
            return (dict(), 404)

    def handle_image_delete(self, digest):
        return "true"

    def catch_all(self, path):
        print("MockServer:: Unhandled request {} /{}".format(request.method, path), file=sys.stderr)
        return ("", 500)

    def init_test(self, known_images=None, report_result="unknown", return_error_500=0):
        self.known_images = known_images or dict()
        self.report_result = report_result
        self.return_error_500 = return_error_500
