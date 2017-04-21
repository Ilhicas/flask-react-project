import os
import sys
import time
import re

from datetime import date, timedelta, datetime
from flask import Flask, request, abort, render_template, request, flash, \
url_for, render_template, redirect, make_response
from flask.json import jsonify
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from models.models import User, Playlist, Song
from config.db import session
from urlparse import urlparse, urljoin




# EB looks for an 'application' callable by default.
application = Flask(__name__)
application.secret_key = '866b6340bb5dfb062adf6cb59ab40e694cea1df58419f389'
login_manager = LoginManager()
login_manager.init_app(application)
login_manager.login_view = "login"


##Requirement 4 @login_required decorator
@login_manager.user_loader
def load_user(token):
  user = session.query(User).filter(User.session_token == token).first()
  return user


#Requirement 3
@application.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return redirect("/")


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
                message = jsonify( {
                    "status": "failed",
                    "message": "something is missing..."
                })
                return render_template('login.html', message=message)
        # We fetch the user with this email
        user = user_exists_email(user_email)
        # The user does not exist...
        if (user == None):
            message = jsonify( {
                "status": "failed",
                "message": "Invalid username or password"
            })

            return render_template('login.html', message=message)

        # We check the password
        if user.check_password(user_password):
            if request.form.get("rememberMe") is not None:
                login_user(user, remember=True)
            else:
                login_user(user, remember=False)
            message = jsonify( {
                "status": "success",
                "message": "Authenticated with success"
            })
            next = request.args.get('next')
            # is_safe_url should check if the url is safe for redirects.
            if not is_safe_url(next):
                return abort(400)

            return redirect(next or "/")

        else:
            message =  jsonify( {
                "status": "failed",
                "message": "Invalid username or password"
        })

        return render_template('login.html', message=message)
    else:
        register = request.args.get('register')
        if register == "true":
            return render_template("register.html")
        else:
            return render_template("login.html")


@application.route("/users", methods=["POST"])
def create_new_user():
    # Handles a json request if the request is json
    if (request.is_json):
        request_data = request.get_json(force = True)
        if 'email' in request_data and 'password' in request_data and 'confirm_password' in request_data:
            user_password = request_data['password']
            user_email = request_data['email']
            if (user_password != request_data['confirm_password']):
                return make_response("Passwords don't match", 400)
        else:
            return make_response("There is no email, password or password confirmation in request", 400)
    # Else, we assume the request is a form
    else:
        user_password = request.form.get('password')
        user_email = request.form.get('email')
        if (user_password != request.form.get('confirm_password')):
            return make_response("Passwords don't match", 400)
        if (user_email == None or user_password == None):
            return make_response("There is no password or password confirmation in request", 400)


    # Create a random session token
    user_token = unicode(os.urandom(24).encode('hex'))

    # Saves new user in the database
    try:
        new_user = User(email = user_email, password = user_password, session_token = user_token)
        # We hash the password
        new_user.set_password()
        session.add(new_user)
        session.commit()
    # Handles any unexpected exception....
    except Exception as e:
        message = jsonify( {
            "status": "failed",
            "message": str(e)
        })
        return render_template('register.html', message = message)

    # Success!
    message = jsonify( {
        "status": "ok",
        "message": "user created with success"
    })
    return redirect("/")


#Requirement 1 and A4
@application.route("/users/<user>", methods=["PUT"])
@login_required
def update_user(user):
    # We get the user sesion_token from the session
    session_token = current_user.get_id()
    # Handles a json request if the request is json
    if (request.is_json):
        request_data = request.get_json(force = True)
        if 'new_password' in request_data and 'password' in request_data and 'confirm_password' in request_data:
            user_password = request_data['password']
            new_password = request_data['new_password']
            confirm_password = request_data['confirm_password']
        else:
            return make_response("There is no new_password, password or password confirmation in request", 400)
    # Else, we assume the request is a form
    else:
        user_password = request.form.get('password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        if (user_email == None or user_password == None):
            return make_response("There is no new_password, password or password confirmation in request", 400)

    try:
        to_update = session.query(User).filter(User.id == user, User.session_token == session_token).first()
    except Exception as e:
        print(e)
        return make_response("Unknown error", 500)

    if to_update is None:
        return make_response("Invalid User", 400)

    if new_password != confirm_password:
        return make_response("Passwords don't match", 400)

    # If the 'old' password is validated
    if to_update.check_password(user_password):
        # We need to create a new session token
        user_token = unicode(os.urandom(24).encode('hex'))
        to_update.session_token = user_token
        to_update.password = new_password
        to_update.set_password()
        session.commit()
        return make_response("User Updated with Success", 200)

    else:
        return make_response("Wrong Password", 400)



@application.route("/users/<int:user>", methods=["GET"])
@login_required
def user_account(user):
    session_id = current_user.get_id(token=False)

    if user == session_id:
        return render_template("user.html", user=session_id)
    else:
        return make_response("Not logged in as that user", 401)

#Requirement 1 - Feito, falta perceber o "return"
@application.route("/users/<int:user>", methods=["DELETE"])
@login_required
def delete_user(user):
    # We get the user sesion_token from the session
    session_token = current_user.get_id()
    try:
        # We search for a user with the specified ID and with the same session_token as the one that made the request
        to_delete = session.query(User).filter(User.session_token==session_token, User.id == user).first()
    # Unexpected exception handling...
    except Exception as e:
        message = "Error... Try again"
        if request.is_json:
            return jsonify( {
                "message": message
            })
        else:
            return render_template('index.html', message= message)
    # If to_delete is None, the user does not exist or the user that made the request is not the same that we want to delete
    if to_delete is None:
        message = "User does not exist or you are not the user"
        if request.is_json:
            return jsonify( {
                "message": message
            })
        else:
            return render_template('index.html', message= message)
    # We logout the user from the session
    logout_user()
    # We delete the user from the database
    session.delete(to_delete)
    # And we commit the change to the db
    session.commit()
    message = "user deleted with success"
    if request.is_json:
        return jsonify( {
            "message": message
        })
    else:
        return render_template("login.html", message= message)

#Requirement 5
@application.route("/playlists", methods=["POST"])
@login_required
def create_playlist():
    #TODO Create method in models.playlist - Attribute Name
    # Handles a json request if the request is json
    if (request.is_json):
        request_data = request.get_json(force = True)
        if 'name' in request_data and 'description' in request_data:
            playlist_name = request_data['name']
            playlist_description = request_data['description']
        else:
            return make_response("There is no name or description in request", 400)
    # Else, we assume the request is a form
    else:
        playlist_name = request.form.get('name')
        playlist_description = request.form.get('description')
        if playlist_name is None or playlist_description is None:
            return make_response("There is no name or description in request", 400)
    user_id = current_user.get_id(token=False)
    new_playlist = Playlist(name = playlist_name, description = playlist_description, user_id = user_id)
    session.add(new_playlist)
    session.commit()
    return make_response("Playlist added with success", 200)


#Requirement 6
@application.route("/playlists/<int:playlist>", methods=["PUT"])
@login_required
def update_playlist(playlist):
    #TODO Update method in models.playlis associated with user, it should allow for adding songs / remove, these are part of the resource as a method and should not be in delete
    user_id = current_user.get_id(token=False)
    if (request.is_json):
        request_data = request.get_json(force = True)
        if 'name' in request_data:
            playlist_name = request_data['name']
        if 'description' in request_data:
            playlist_description = request_data['description']
        else:
            return make_response("There is no name or description in request", 400)
    # Else, we assume the request is a form
    else:
        playlist_name = request.form.get('name')
        playlist_description = request.form.get('description')

    try:
        to_update = session.query(Playlist).filter(Playlist.id == playlist, Playlist.user_id == user_id).first()
    except Exception as e:
        print(e)
        return make_response("Unknown error", 500)

    if to_update is None:
        return make_response("There is no such playlist", 400)

    if playlist_name is not None:
        to_update.name = playlist_name
    if playlist_description is not None:
        to_update.description = playlist_description


    session.commit()

    print(to_update.name)
    print(to_update.description)

    return make_response("Playlist updated with success", 200)

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
    # To order in sql alchemy: query = session.query(Playlist).filter(Playlist.user_id == current_user.get_id(token = False).ordery_by('Playlist.name'))
    #TODO Playlists only of user id
    query = session.query(Playlist).filter(Playlist.user_id == current_user.get_id(token=False)).order_by(Playlist.name)
    playlists = [row.__dict__ for row in query.all()]

    if request.is_json:
        return jsonify(playlists)
    else:
        user = current_user.get_id(token=False)
        return render_template("playlists.html", user=user, playlists=playlists)

#Requirement 8
#Maximum URI depth for REST reached in this endpoint Collection - Resource - Collection
@application.route("/playlists/<int:playlist>/songs", methods=["GET"])
@login_required
def get_songs_in_playlist(playlist):

    if (my_playlist = session.query(Playlist).filter(Playlist.id == playlist).first()) is None:
        return make_response("Not your playlist", 401)

    for song in my_playlist.songs:
        print song
    return make_response("Songs fetched", 200)
    # if request.is_json:
    #     return jsonify(songs)
    # else:
    #     user = current_user.get_id(token=False)
    #     return render_template("playlists.html", user=user, playlists=playlists)



#Requirement 11
@application.route("/songs", methods=["POST"])
@login_required
def create_song():
    #TODO !Implement song upload!
    #TODO Create method in models.playlist - Attribute Name
    # Handles a json request if the request is json
    if (request.is_json):
        request_data = request.get_json(force = True)
        if 'name' in request_data and 'album' in request_data and 'artist' in request_data:
            song_name = request_data['name']
            song_album = request_data['album']
            song_artist = request_data['artist']
        else:
            return make_response("There is no name, album or artist in request", 400)
    # Else, we assume the request is a form
    else:
        song_name = request.form.get('name')
        song_album = request.form.get('album')
        song_artist = request.form.get('artist')
        if song_name is None or song_album is None or song_artist is None:
            return make_response("There is no name or description in request", 400)

    user_id = current_user.get_id(token=False)
    new_song = Song(name = song_name, album = song_album, artist = song_artist, user_id = user_id)
    session.add(new_song)
    session.commit()
    return make_response("Song added with success", 200)

#Requirement 12 and A5
@application.route("/songs/<song>", methods=["DELETE"])
@login_required
def delete_song(song):
    #TODO Delete method in models.song, only if user in session is the creator
    pass

@application.route('/')
@login_required
def main():
    user_token = current_user.get_id(token=False)

    return render_template('index.html', user=user_token)

@login_manager.unauthorized_handler
def unauthorized():
    return redirect("/login")

def user_exists_email(email):
  user = session.query(User).filter(User.email == email).first()
  return user


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


if __name__ == '__main__':
    application.run(debug=True, port=9000)
