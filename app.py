import pymongo

import datetime

from bson.objectid import ObjectId

from pymongo.mongo_client import MongoClient

from pymongo.server_api import ServerApi

from flask import Flask, render_template, request, redirect, url_for, flash, session

from passlib.hash import sha256_crypt

app = Flask('loginsystem')

app.secret_key = "123456789"

uri= "mongodb+srv://lauvacat:Ow42onZpO4fqruxj@cluster0.7fifn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = pymongo.MongoClient(uri, tls=True, tlsAllowInvalidCertificates=True)
db = client.loginsystem

@app.route('/',methods =['GET','POST'])

def register():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        doc = {}
        password = request.form["password"]
        password1 = sha256_crypt.hash(password)
        doc["password1"] = password1
        doc["email"] = request.form["email"]
            
        db.users.insert_one(doc)
        flash('Account created successfully!')
        return redirect('/login')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        doc = {'email':request.form['email']}

        found = db.users.find_one(doc)
        
        password = request.form["password"]
        request1 = request.form
        request2 = request1.get("password")
        print(password, found["password1"])
        if found is None:
            flash('The email and password you entered did not match our record. Please double check and try again.')
            return redirect('/login')

        if sha256_crypt.verify(password, found["password1"]):
            print("correct password")
            session['user-info'] = {'email': found['email']}
            return redirect('/home')
        else:
            print('wrong')
            flash('incorrect')
            return redirect('/')



@app.route('/home', methods = ['GET', 'POST'])
def home():
    print('hello')
    if 'email' not in session:
        print('email')
        flash('You must login')
        return redirect('/')
    else:
        return render_template('home.html')

@app.route('/logout')
def logout():
        session.clear()
        flash('logout successful')
        return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
