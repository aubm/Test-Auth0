import jwt
import os
import base64

from functools import wraps
from flask import Flask, request, jsonify, _request_ctx_stack
from werkzeug.local import LocalProxy
from flask_cors import cross_origin

app = Flask(__name__)
# Authentication annotation
current_user = LocalProxy(lambda: _request_ctx_stack.top.current_user)

CLIENT_SECRET = 'CLIENT_SECRET'
AUDIENCE = 'CLIENT_ID'


# Authentication attribute/annotation
def authenticate(error):
    resp = jsonify(error)

    resp.status_code = 401

    return resp


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return authenticate(
                {'code': 'authorization_header_missing', 'description': 'Authorization header is expected'})

        parts = auth.split()

        if parts[0].lower() != 'bearer':
            return {'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}
        elif len(parts) == 1:
            return {'code': 'invalid_header', 'description': 'Token not found'}
        elif len(parts) > 2:
            return {'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}

        token = parts[1]
        try:
            payload = jwt.decode(token, CLIENT_SECRET, audience=AUDIENCE)
        except jwt.ExpiredSignature:
            return authenticate({'code': 'token_expired', 'description': 'token is expired'})
        except jwt.InvalidAudienceError:
            return authenticate(
                {'code': 'invalid_audience', 'description': 'incorrect audience, expected: YOUR_CLIENT_ID'})
        except jwt.DecodeError:
            return authenticate({'code': 'token_invalid_signature', 'description': 'token signature is invalid'})

        _request_ctx_stack.top.current_user = user = payload
        return f(*args, **kwargs)

    return decorated


# Controllers API

# This doesn't need authentication
@app.route("/ping")
@cross_origin(headers=['Content-Type', 'Authorization'])
def ping():
    return '{"description":"All good. You don\'t need to be authenticated to call this"}'


# This does need authentication
@app.route("/secured/ping")
@cross_origin(headers=['Content-Type', 'Authorization'])
@requires_auth
def secured_ping():
    return '{"description":"All good. You only get this message if you\'re authenticated"}'


if __name__ == "__main__":
    app.run()
