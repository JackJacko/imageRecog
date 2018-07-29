from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt
import numpy
import tensorflow as tf
import requests
import subprocess
import json

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.imgRecogDB
Users = db["Users"]

def verify_pw(usr, pwd):
    h_pwd = Users.find({"Username":usr})[0]["Password"]

    if bcrypt.hashpw(pwd.encode('utf8'), h_pwd) == h_pwd:
        return True
    else:
        return False

def check_username(usr):
    if Users.find({"Username":usr},{"Username":1}).count() > 0:
        return True
    else:
        return False

def check_tokens(usr):
    tokenNum = Users.find({"Username":usr})[0]["Tokens"]
    return tokenNum

def generate_retJson(status,message):
    retJson = {
        "Message": message,
        "Status code": status
    }
    return jsonify(retJson)

class Register(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data:
            return generate_retJson(301,"An error happened: Input data is missing.")
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        # check if username is in use
        if check_username(usr):
            return generate_retJson(302,"An error happened: Username is already taken.")
        # hash the password
        h_pwd = bcrypt.hashpw(pwd.encode('utf8'), bcrypt.gensalt())
        # store username and hashed password
        Users.insert_one({
            "Username": usr,
            "Password": h_pwd,
            "Tokens": 10
        })
        # confirm successful registration
        return generate_retJson(200,"Your registration was successful.")

class Identify(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data or 'Address' not in Data:
            return generate_retJson(301,"An error happened: Input data is missing.")
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        url = Data['Address']
        # check if username is registered
        if not check_username(usr):
            return generate_retJson(303,"An error happened: Username not present in database. Please register.")
        # check if password is correct
        if not verify_pw(usr, pwd):
            return generate_retJson(304,"An error happened: Wrong password.")
        # check token amount
        tkn = check_tokens(usr)
        if tkn <= 0:
            return generate_retJson(305,"An error happened: Insufficient tokens. Please buy more tokens.")
        # download image from URL and identify it using tensorflow
        r = requests.get(url)
        retJson = {}
        with open('temp.jpg', 'wb') as f:
            f.write(r.content)
            proc = subprocess.Popen('python classify_image.py --model_dir=. --image_file=./temp.jpg', stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            ret = proc.communicate()[0]
            proc.wait()
            with open("text.txt") as g:
                retJson = json.load(g)
        # Update tokens and report identification results
        Users.update_one({
            "Username": usr
        }, {
            "$set": {
                "Tokens": tkn - 1
            }
        })
        retJson["Remaining tokens"]=check_tokens(usr)
        return retJson

class Refill(Resource):
    def post(self):
        # get posted data
        Data = request.get_json()
        # check data for missing input
        if 'Username' not in Data or 'Password' not in Data or 'RefillAmount' not in Data:
            return generate_retJson(301,"An error happened: Input data is missing.")
        # assign data to variables
        usr = Data['Username']
        pwd = Data['Password']
        rfl = Data['RefillAmount']
        # check if username is registered
        if not check_username(usr):
            return generate_retJson(303,"An error happened: Username not present in database. Please register.")
        # check if password is correct
        if not verify_pw("admin", pwd):
            return generate_retJson(306,"An error happened: Wrong admin password. Admin access only.")
        # update tokens and return success
        tkn = check_tokens(usr)
        Users.update_one({
            "Username": usr
        }, {
            "$set": {
                "Tokens": tkn + rfl
            }
        })
        retJson = {
            "Status code": 200,
            "Message": "Tokens successfully refilled.",
            "Current token amount": check_tokens(usr)
        }
        return jsonify(retJson)

api.add_resource(Register, "/signup")
api.add_resource(Identify, "/identify")
api.add_resource(Refill, "/refill")

if __name__=="__main__":
    app.run(host ='0.0.0.0', debug = True)
