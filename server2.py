from datetime import timedelta, datetime, timezone
from functools import wraps

import redis
import secrets
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt, create_refresh_token, set_access_cookies
from pymongo import MongoClient
from flask_bcrypt import Bcrypt

ACCESS_EXPIRES = timedelta(hours=1)

app = Flask(__name__)
# app.config["JWT_COOKIE_SECURE"] = False
# app.config["JWT_TOKEN_LOCATION"] = ["cookies"] 
app.config["JWT_SECRET_KEY"] = secrets.token_urlsafe(16)
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = ACCESS_EXPIRES

bcrypt = Bcrypt(app)

jwt = JWTManager(app)

client = MongoClient("mongodb+srv://Dragon6:Dragon6@cluster0.koioa.mongodb.net/?retryWrites=true&w=majority")
db = client["sample_mflix"]
users_collection = db["users"]

jwt_redis_blocklist = redis.StrictRedis(
    host="localhost", port=6379, db=0, decode_responses=True
)

@jwt.token_in_blocklist_loader
def check_if_token_is_revoked(jwt_header, jwt_payload: dict):
    jti = jwt_payload["jti"]
    token_in_redis = jwt_redis_blocklist.get(jti)
    return token_in_redis is not None

# @app.after_request
# def refresh_expiring_jwts(response):
#     try:
#         exp_timestamp = get_jwt()["exp"]
#         now = datetime.now(timezone.utc)
#         target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
#         if target_timestamp > exp_timestamp:
#             access_token = create_access_token(identity=get_jwt_identity())
#             set_access_cookies(response, access_token)
#         return response
#     except (RuntimeError, KeyError):
#         # Case where there is not a valid JWT. Just return the original response
#         return response

def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims['admin']:
                return fn(*args, **kwargs)
            else:
                return jsonify({'msg':'Admin Only!'}), 403

        return decorator

    return wrapper


@app.route('/api/v1/signup', methods=['POST'])
def signup():
    new_user = request.get_json()
    invalid_username = users_collection.find_one({'username': new_user['username']})
    invalid_email = users_collection.find_one({'email': new_user['email']})
    if invalid_username:
        return jsonify({'msg': 'Username is already taken.'}), 409
    elif invalid_email:
        return jsonify({'msg': 'Email is already taken.'}), 409
    else:
        new_user['password'] = bcrypt.generate_password_hash(new_user['password']).decode('utf-8')
        users_collection.insert_one(new_user)
        return jsonify({'msg': 'User created successfully.'}), 201

@app.route('/api/v1/login', methods=['POST'])
def login():
    login_details = request.get_json()
    verified_user = users_collection.find_one({'username': login_details['username']})

    if verified_user:
        if bcrypt.check_password_hash(verified_user['password'], login_details['password']):
            isAdmin = verified_user['username'] == 'admin'
            access_token = create_access_token(identity=verified_user['username'], additional_claims={'admin': isAdmin}, fresh=True)
            # refresh_token = create_refresh_token(verified_user['username'])
            return jsonify({
                'access_token': access_token, 
                # 'refresh_token': refresh_token
            }), 200
    return jsonify({'msg': 'The username or password is incorrect'}), 401

@app.route('/api/v1/loadUser', methods=['GET'])
@jwt_required()
#@verify_jwt_in_request()
def loadUser():
    user = get_jwt_identity()
    user_data = users_collection.find_one({'username': user})
    if user_data:
        del user_data['_id'], user_data['password']
        return jsonify({'profile': user_data}), 200
    else:
        return jsonify({'msg': 'Profile not found'}), 404

@app.route('/api/v1/logout', methods=['DELETE'])
@jwt_required()
def logout():
    token = get_jwt()
    jti = token['jti']
    # ttype = token['type']
    jwt_redis_blocklist.set(jti, '', ex=ACCESS_EXPIRES)
    return jsonify(msg=f"Token successfully revoked"), 200

@app.route('/api/v1/deleteUser', methods=['DELETE'])
@admin_required()
def deleteUser():
    user_to_delete = request.get_json()
    user_exists = users_collection.find_one({'username': user_to_delete['username']})
    if user_exists:
        users_collection.delete_one({'username': user_to_delete['username']})
        return jsonify(msg='User ' + user_to_delete['usernmae'] + ' was deleted.'), 200
    else:
        return jsonify(msg='User ' + user_to_delete['usernmae'] + ' does not exist.'), 409

if __name__ == '__main__':
    app.run(port=8080, debug=True) 