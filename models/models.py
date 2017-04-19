from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, DateTime, \
Float, Table, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from config.db import engine
from werkzeug.security import generate_password_hash, \
     check_password_hash
from sqlalchemy.sql import func
from flask_login import UserMixin


Base = declarative_base()

song_to_playlist = Table('song_to_playlist', Base.metadata,
    Column('song_id', ForeignKey('songs.id'),
    primary_key=True),Column('playlist_id',
    ForeignKey('playlists.id'), primary_key=True))

user_to_playlist = Table('user_to_playlist', Base.metadata,
    Column('users_id', ForeignKey('users.id'),
    primary_key=True),Column('playlist_id',
    ForeignKey('playlists.id'), primary_key=True))

class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key = True)
    email = Column(String(128), unique = True)
    password = Column(String(300))
    session_token = Column(String(128, convert_unicode=True))
    playlists = relationship("Playlist", secondary = user_to_playlist, cascade = "all")


    def __repr__(self):
        return "<User(user_id='%s')>" % (self.id)

    def check_password(self, password):
       return check_password_hash(self.password, password)

    def set_password(self):
       self.password = generate_password_hash(self.password)

    def get_id(self):
        return self.session_token

class Song(Base):
    __tablename__ = 'songs'
    id = Column(Integer, Sequence('song_id_seq'), primary_key = True)
    name = Column(String(128))
    album = Column(String(128))
    artist = Column(String(128))
    playlists = relationship("Playlist", secondary = song_to_playlist, cascade = "all")


class Playlist(Base):
    __tablename__ = 'playlists'
    id = Column(Integer, Sequence('playlist_id_seq'), primary_key = True)
    name = Column(String(128))
    description = Column(Text)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    users = relationship("User", secondary = user_to_playlist, cascade = "save-update")
    songs = relationship("Song", secondary = song_to_playlist, cascade = "save-update")


Base.metadata.create_all(engine)
