from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, Date, Float, Table, Text
from sqlalchemy.ext.declarative import declarative_base
Base = declarative_base()

song_to_playlist = Table('song_to_playlist', Base.metadata,
    Column('song_id', ForeignKey('songs.id'),
    primary_key=True),Column('playlist_id',
    ForeignKey('playlists.id'), primary_key=True))

user_to_playlist = Table('user_to_playlist', Base.metadata,
    Column('users_id', ForeignKey('user.id'),
    primary_key=True),Column('playlists_id',
    ForeignKey('playlist.id'), primary_key=True))


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, Sequence('user_id_seq'), primary_key = True)
    email = Column(String(128), unique = True)
    password = Column(String(300))
    session_token = Column(String(128))
    playlists = relationship("Playlist", secondary = user_to_playlist, cascade = "all")

    def __repr__(self):
        return "<User(user_id='%s')>" % (self.id)

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
    users = relationship("User", secondary = user_to_playlist, cascade = "save-update")
    songs = relationship("Song", secondary = song_to_playlist, cascade = "save-update")