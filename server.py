import datetime
import bcrypt
#import redis
import certifi
import json
from bson import json_util
from flask import Flask, request, render_template, redirect, jsonify, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
from flask_bcrypt import generate_password_hash, check_password_hash
from pymongo import MongoClient

app = Flask(__name__)
jwt = JWTManager(app)
ACCESS_EXPIRES = datetime.timedelta(days=1)
app.config['JWT_TOKEN_LOCATION'] = ["headers", "cookies", "json", "query_string"]
app.config['JWT_SECRET_KEY'] = 'Your_Secret_Key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = ACCESS_EXPIRES

client = MongoClient("mongodb+srv://Dragon6:Dragon6@cluster0.koioa.mongodb.net/TaskForceDragon?retryWrites=true&w=majority", tlsCAFile=certifi.where())
db = client.TaskForceDragon
users_collection = db.users

def get_identity_if_loggedin():
    try:
        verify_jwt_in_request()
        return get_jwt_identity()
    except Exception:
        pass

@app.route("/", methods=["GET"])
def homePage():
    return render_template('index.html')

@app.route("/login", methods=["GET"])
def loginPage():
    return render_template('login.html')

@app.route("/profile", methods=["GET"])
def profilePage():
    return render_template('profile.html')

@app.route("/admin", methods=["GET"])
def adminPage():
    return render_template('admin.html')

@app.route("/api/signup", methods=["POST"])
def signup():
    new_user = request.get_json() # store the json body request
    new_user["password"] = generate_password_hash(new_user["password"])
    doc = users_collection.find_one({"username": new_user["username"]}) # check if user exist
    if not doc:
        users_collection.insert_one(new_user)
        return jsonify({'msg': 'User created successfully'}), 201
    else:
        return jsonify({'msg': 'Username already exists'}), 409


@app.route("/api/login", methods=["POST"]) # Returns the log in page as well logs in
def login():
    req = request.get_json()
    user = users_collection.find_one({'username': req['username']})
    if user:
        if check_password_hash(user['password'], req['password']):
            print("User Exist")
            access_token = create_access_token(identity=user['username'])
            return jsonify(msg='Logged in',access_token=access_token), 200
    return jsonify({'msg': 'The username or password is incorrect'}), 401

@app.route("/api/loadUser", methods=["POST"])
@jwt_required()
def loadUser():
    user_id = get_jwt_identity()
    user = users_collection.find_one({'username': user_id})
    if user:
        user_data = json.loads(json_util.dumps(user))
        return jsonify({'msg': 'Profile found','profile': user_data}), 200
    else:
        return jsonify({'msg': 'Profile not found'}), 404

@app.route("/api/selectUser", methods=["POST"])
@jwt_required()
def selectUser():
    data = request.get_json()
    user = users_collection.find_one({'username': data['username']})
    if user:
        user_data = json.loads(json_util.dumps(user))
        return jsonify({'msg': 'Profile found','profile': user_data}), 200
    else:
        return jsonify({'msg': 'Profile not found'}), 200

@app.route("/api/checkUserLoggedIn", methods=["POST"])
def checkUserLoggedIn():
    user = get_identity_if_loggedin()
    if user:
        return jsonify({'msg': 'User logged in', 'username': user})
    else:
        return jsonify({'msg': 'No user logged in'})

@app.route("/api/editUser", methods=["POST", "DELETE"])
@jwt_required()
def editUser():
    if request.method == 'DELETE':
        data = request.get_json()
        users_collection.delete_one({'username': data['username']})
        return jsonify({'msg': 'User deleted'}), 200
    elif request.method == 'POST':
        data = request.get_json()
        for item in data:
            if item:
                i = item
                v = data[item]
                query = {'username': data['username']}
                update = {"$set": {i: v}}
                users_collection.update_one(query, update, upsert=True)
        return jsonify({'msg': 'User updated successfully!'}), 200

@app.route("/api/authAdmin", methods=["POST"])
@jwt_required()
def authAdmin():
    if get_jwt_identity() == 'admin':
        return jsonify({'msg': 'admin'}), 200
    else:
        return jsonify({'msg': 'blocked'}), 403

if __name__ == '__main__':
    app.run(port=8080) 
