from functools import wraps

from crypt import methods
import json
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from pymongo import MongoClient
from flask_bcrypt import Bcrypt

app = Flask(__name__)

bcrypt = Bcrypt(app)

jwt = JWTManager(app)

client = MongoClient("mongodb+srv://Dragon6:Dragon6@cluster0.koioa.mongodb.net/?retryWrites=true&w=majority")
db = client["sample_mflix"]
users_collection = db["users"]

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
            access_token = create_access_token(identity=verified_user['username'], additional_claims={'admin': isAdmin})
            return jsonify(access_token=access_token), 200
    return jsonify({'msg': 'The username or password is incorrect'}), 401

@app.route('/api/v1/loadUser', methods=['GET'])
@jwt_required()
def loadUser():
    return "Sign up"

@app.route('/api/v1/logout', methods=['DELETE'])
@jwt_required()
def logout():
    return "Sign up"

@app.route('/api/v1/deleteUser', methods=['DELETE'])
@admin_required()
def deleteUser():
    return 'delete'

if __name__ == '__main__':
    app.run(port=8080, debug=True) 