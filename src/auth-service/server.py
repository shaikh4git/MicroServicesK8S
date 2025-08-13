import jwt, datetime, os
import psycopg2
from flask import Flask, request, jsonify
from prometheus_client import Counter

server = Flask(__name__)

# Prometheus metric for tracking unauthorized uploads
unauth_count = Counter('unauthorized_uploads_total', 'Number of unauthorized upload attempts')

def get_db_connection():
    conn = psycopg2.connect(
        host=os.getenv('DATABASE_HOST'),
        database=os.getenv('DATABASE_NAME'),
        user=os.getenv('DATABASE_USER'),
        password=os.getenv('DATABASE_PASSWORD'),
        port=5432
    )
    return conn


@server.route('/login', methods=['POST'])
def login():
    auth_table_name = os.getenv('AUTH_TABLE')
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return 'Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    conn = get_db_connection()
    cur = conn.cursor()
    query = f"SELECT email, password FROM {auth_table_name} WHERE email = %s"
    cur.execute(query, (auth.username,))
    user_row = cur.fetchone()
    cur.close()
    conn.close()

    if not user_row:
        return 'Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    email, password = user_row
    if auth.username != email or auth.password != password:
        return 'Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    return CreateJWT(auth.username, os.environ['JWT_SECRET'], True)


def CreateJWT(username, secret, authz):
    return jwt.encode(
        {
            "username": username,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1),
            "iat": datetime.datetime.now(tz=datetime.timezone.utc),
            "admin": authz,
        },
        secret,
        algorithm="HS256",
    )


@server.route('/validate', methods=['POST'])
def validate():
    encoded_jwt = request.headers.get('Authorization')
    
    if not encoded_jwt:
        return 'Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}

    encoded_jwt = encoded_jwt.split(' ')[1]
    try:
        decoded_jwt = jwt.decode(encoded_jwt, os.environ['JWT_SECRET'], algorithms=["HS256"])
    except:
        return 'Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'}
    
    return decoded_jwt, 200


@server.route('/upload', methods=['POST'])
def upload():
    token = request.headers.get('Authorization')
    if not token:
        unauth_count.inc()
        return jsonify({"error": "Unauthorized"}), 401

    try:
        token = token.split(' ')[1]
        jwt.decode(token, os.environ['JWT_SECRET'], algorithms=["HS256"])
    except Exception as e:
        unauth_count.inc()
        return jsonify({"error": "Unauthorized", "message": str(e)}), 401

    # Here you can handle your file upload logic
    return jsonify({"status": "success", "message": "File uploaded"}), 200


if __name__ == '__main__':
    server.run(host='0.0.0.0', port=5000)
