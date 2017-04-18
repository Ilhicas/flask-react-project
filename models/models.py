from sqlalchemy import Column, Integer, String, Sequence, ForeignKey, Date, Float, Table, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()



class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, Sequence('user_id_seq'), primary_key = True)
    email = Column(String(60))
    amount = Column(Float())
    def __repr__(self):
        return "<User(user_id='%s')>" % (self.id)
