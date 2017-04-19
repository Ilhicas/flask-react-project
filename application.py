import sys
import json
import time
import re

from datetime import date, timedelta, datetime
from flask import Flask, request, abort, render_template, request, flash, url_for, render_template, redirect
from flask_login import LoginManager, login_required, login_user, logout_user
from models.models import User
from config.db import session

from werkzeug.security import generate_password_hash, \
     check_password_hash


# EB looks for an 'application' callable by default.
application = Flask(__name__)

##Requirement 4 @login_required decorator


#Requirement 3
@application.route("/logout", methods=["GET"])
@login_required
def logout():
    pass

#Requirement 2
@application.route("/login", methods=["GET"])
def login():
    #TODO There must be some validation method for form in users class
    pass

#Requirement 1
@application.route("/users", methods=["POST"])
def create_new_user():
    pass

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


def set_password(password):
   return generate_password_hash(password)

def check_password(password):
   return check_password_hash(self.pw_hash, password)

if __name__ == '__main__':
    application.run(debug=True, port=9000)
