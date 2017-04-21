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


class User(Base, UserMixin):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key = True)
    email = Column(String(128), unique = True)
    password = Column(String(300))
    session_token = Column(String(128, convert_unicode=True))
    playlists= relationship("Playlist", back_populates="users")

    def __repr__(self):
        return "<User(user_id='%s')>" % (self.id)

    def check_password(self, password):
       return check_password_hash(self.password, password)

    def set_password(self):
       self.password = generate_password_hash(self.password)

    def get_id(self, token=True):
        if token is True:
            return self.session_token
        else:
            return self.id


class Song(Base):
    __tablename__ = 'songs'
    id = Column(Integer, Sequence('song_id_seq'), primary_key = True) # unique ID
    name = Column(String(128)) # Name of the song
    album = Column(String(128)) # Album name
    artist = Column(String(128)) # Artist name
    hidden = Column(Boolean, default=False) # If the song gets deleted, this should be marked as true
    playlists = relationship("Playlist", secondary = song_to_playlist, cascade = "all")


class Playlist(Base):
    __tablename__ = 'playlists'
    id = Column(Integer, Sequence('playlist_id_seq'), primary_key = True)
    name = Column(String(128))
    description = Column(Text)
    time_created = Column(DateTime(timezone=True), server_default=func.now())
    time_updated = Column(DateTime(timezone=True), onupdate=func.now())
    user_id = Column(Integer, ForeignKey('users.id'))
    users = relationship("User", back_populates="playlists")
    songs = relationship("Song", secondary = song_to_playlist, cascade = "save-update")


Base.metadata.create_all(engine)
