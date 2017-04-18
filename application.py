import os
import sys
import json
import time
import re
import psycopg2

from datetime import date, timedelta, datetime
from flask import Flask, request
from models.models import User

# EB looks for an 'application' callable by default.
application = Flask(__name__)


@application.route('/')
def main():
    return "Hello world", 200

if __name__ == '__main__':
    application.run(debug=True)
