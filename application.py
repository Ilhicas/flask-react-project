import os
import sys
import json
import time
import re

from datetime import date, timedelta, datetime
from flask import Flask, request, abort, render_template, request, flash, url_for, render_template, redirect
from flask.json import jsonify
from flask_login import LoginManager, login_required, login_user, logout_user
from models.models import User
from config.db import session




# EB looks for an 'application' callable by default.
application = Flask(__name__)

##Requirement 4 @login_required decorator


#Requirement 3
@application.route("/logout", methods=["GET"])
@login_required
def logout():
    pass

#Requirement 2
@application.route("/login", methods=["GET", "POST"])
def login():
    #TODO We still have to "login" the user in the session!
    if request.method == "POST":
        if (request.is_json):
            request_data = request.get_json(force = True)
            if 'email' in request_data and 'password' in request_data:
                user_email = request_data['email']
                user_password = request_data['password']

            else:
                return jsonify( {
                    "status": "failed",
                    "message": "something is missing..."
                })
        # Else, we assume the request is a form
        else:
            user_email = request.form.get('email')
            user_password = request.form.get('password')
            if (user_email == None or user_password == None):
                return jsonify( {
                    "status": "failed",
                    "message": "something is missing..."
                })

        # We fetch the user with this email
        user = user_exists(user_email)
        # The user does not exist...
        if (user == None):
            return jsonify( {
                "status": "failed",
                "message": "Invalid username or password"
            })

        # We check the password
        if user.check_password(user_password):
            #TODO Authenticate user in session
            return jsonify( {
                "status": "success",
                "message": "Authenticated with success"
            })

        else:
            return jsonify( {
                "status": "failed",
                "message": "Invalid username or password"
        })

    else:
        #TODO O que queres fazer aqui?
        pass

#Requirement 1
@application.route("/users", methods=["POST"])
def create_new_user():
    # Handles a json request if the request is json
    if (request.is_json):
        request_data = request.get_json(force = True)
        if 'email' in request_data and 'password' in request_data and 'confirm_password' in request_data:
            user_email = request_data['email']
            user_password = request_data['password']
            if (user_password != request_data['confirm_password']):
                return jsonify( {
                    "status": "failed",
                    "message": "password and confirm_password don't match"
                })
        else:
            return jsonify( {
                "status": "failed",
                "message": "something is missing..."
            })
    # Else, we assume the request is a form
    else:
        user_email = request.form.get('email')
        user_password = request.form.get('password')
        if (user_password != request.form.get('confirm_password')):
            return jsonify( {
                "status": "failed",
                "message": "password and confirm_password don't match"
            })
        if (user_email == None or user_password == None):
            return jsonify( {
                "status": "failed",
                "message": "something is missing..."
            })

    # If the email already exists...
    if (user_exists(user_email) != None):
        return jsonify( {
            "status": "failed",
            "message": "email already in use"
        })
    # And create a random session token
    user_token = os.urandom(24).encode('hex')

    # Saves new user in the database
    try:
        new_user = User(email = user_email, password = user_password, session_token = user_token)
        # We hash the password
        new_user.set_password()
        session.add(new_user)
        session.commit()
    # Handles any unexpected exception....
    except Exception as e:
        return jsonify( {
            "status": "failed",
            "message": str(e)
        })

    # Success!
    return jsonify( {
        "status": "ok",
        "message": "user created with success"
    })


#Requirement 1 and A4
@application.route("/users/<user>", methods=["PUT"])
@login_required
def update_user():
    #TODO Session must be equal to user to update
    pass

#Requirement 1
@application.route("/users/<user>", methods=["DELETE"])
@login_required
def delete_user():
    #TODO Session must be equal to user to delete
    pass

#Requirement 5
@application.route("/playlists", methods=["POST"])
@login_required
def create_playlist():
    #TODO Create method in models.playlist - Attribute Name
    pass

#Requirement 6
@application.route("/playlists/<playlist>", methods=["PUT"])
@login_required
def update_playlist(playlist):
    #TODO Update method in models.playlis associated with user, it should allow for adding songs / remove, these are part of the resource as a method and should not be in delete
    pass

#Requirement 9
@application.route("/playlists", methods=["DELETE"])
@login_required
def delete_playlist():
    #TODO Delete method in playlists song, only the relation should be eliminated, songs are to be stored
    pass

#Requirement 7 and A4
@application.route("/playlists", methods=["GET"])
@login_required
def get_playlists():
    #TODO Get method in models.playlis associated with user according to request.args order by Name | Creation Date | Size
    #Should default to ascending order by name A to Z
    pass

#Requirement 8
#Maximum URI depth for REST reached in this endpoint Collection - Resource - Collection
@application.route("/playlists/<playlist>/songs", methods=["GET"])
@login_required
def get_songs_in_playlist(playlist):
    #TODO Get method in models.playlis for all related songs
    pass


#Requirement 11
@application.route("/songs", methods=["POST"])
@login_required
def create_song():
    #TODO Create method in models.song
    pass

#Requirement 12 and A5
@application.route("/songs/<song>", methods=["DELETE"])
@login_required
def delete_song(song):
    #TODO Delete method in models.song, only if user in session is the creator
    pass


@application.route('/')
def main():
    return "Hello world", 200


def user_exists(email):
  user = session.query(User).filter(User.email == email).first()
  return user


if __name__ == '__main__':
    application.run(debug=True, port=9000)
