import os, gridfs, pika, json
from flask import Flask, request, send_file, jsonify, Response
from flask_pymongo import PyMongo
from auth import validate
from auth_svc import access as access_svc
from storage import util
from bson.objectid import ObjectId

# Prometheus metrics
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

unauth_count = Counter("unauthorized_requests_total", "Unauthorized requests")
upload_count = Counter("uploads_total", "Successful uploads")

server = Flask(__name__)

mongo_video = PyMongo(server, uri=os.environ.get("MONGODB_VIDEOS_URI"))
mongo_mp3 = PyMongo(server, uri=os.environ.get("MONGODB_MP3S_URI"))

fs_videos = gridfs.GridFS(mongo_video.db)
fs_mp3s = gridfs.GridFS(mongo_mp3.db)

connection = pika.BlockingConnection(pika.ConnectionParameters(host="rabbitmq", heartbeat=0))
channel = connection.channel()

@server.route("/login", methods=["POST"])
def login():
    token, err = access_svc.login(request)
    if not err:
        # token should already be a string/JSON as your client expects
        return token
    return (err, 401) if isinstance(err, str) else (jsonify(err), 401)

@server.route("/upload", methods=["POST"])
def upload():
    token_payload_str, err = validate.token(request)
    if err:
        unauth_count.inc()
        return (err, 401) if isinstance(err, str) else (jsonify(err), 401)

    try:
        token_payload = json.loads(token_payload_str)
    except Exception:
        return jsonify({"error": "invalid token payload"}), 400

    if not token_payload.get("admin"):
        unauth_count.inc()
        return jsonify({"error": "not authorized"}), 401

    if len(request.files) != 1:
        return jsonify({"error": "exactly 1 file required"}), 400

    # Grab the single file from the form
    _, f = next(iter(request.files.items()))

    try:
        err = util.upload(f, fs_videos, channel, token_payload)
        if err:
            # util.upload seems to return an error string/obj on failure
            return (err, 400) if isinstance(err, str) else (jsonify(err), 400)
        upload_count.inc()
        return jsonify({"status": "success"}), 200
    except Exception as e:
        # log if you have a logger; returning generic message
        return jsonify({"error": "internal server error"}), 500

@server.route("/download", methods=["GET"])
def download():
    token_payload_str, err = validate.token(request)
    if err:
        unauth_count.inc()
        return (err, 401) if isinstance(err, str) else (jsonify(err), 401)

    try:
        token_payload = json.loads(token_payload_str)
    except Exception:
        return jsonify({"error": "invalid token payload"}), 400

    if not token_payload.get("admin"):
        unauth_count.inc()
        return jsonify({"error": "not authorized"}), 401

    fid_string = request.args.get("fid")
    if not fid_string:
        return jsonify({"error": "fid is required"}), 400

    try:
        out = fs_mp3s.get(ObjectId(fid_string))  # GridOut is file-like; ok for send_file
        return send_file(out, download_name=f"{fid_string}.mp3")
    except Exception as e:
        # log e if desired
        return jsonify({"error": "internal server error"}), 500

@server.route("/metrics")
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

if __name__ == "__main__":
    server.run(host="0.0.0.0", port=8080)
