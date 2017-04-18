import os
import sys
import json
import time
import re

from datetime import date, timedelta, datetime
from flask import Flask, request
from models.models import User
from werkzeug.security import generate_password_hash, \
     check_password_hash

# EB looks for an 'application' callable by default.
application = Flask(__name__)


@application.route('/')
def main():
    return "Hello world", 200


def set_password(password):
   return generate_password_hash(password)

def check_password(password):
   return check_password_hash(self.pw_hash, password)

if __name__ == '__main__':
    application.run(debug=True)
