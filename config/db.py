import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, relationship
import psycopg2
# Database
DATABASES = {
    'default': {
        'NAME': 'songES',
        'USER': 'postgres',
        'PASSWORD': '14243160',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

if 'RDS_HOSTNAME' in os.environ:
    DATABASES = {
        'default': {
            'NAME': os.environ['RDS_DB_NAME'],
            'USER': os.environ['RDS_USERNAME'],
            'PASSWORD': os.environ['RDS_PASSWORD'],
            'HOST': os.environ['RDS_HOSTNAME'],
            'PORT': os.environ['RDS_PORT'],
        }
    }


engine = create_engine('postgresql://'+DATABASES['default'].get('USER')+':'+ DATABASES['default'].get('PASSWORD') + '@'+DATABASES['default'].get('HOST')+':'+ DATABASES['default'].get('PORT') +'/'+ DATABASES['default'].get('NAME'))


Session = sessionmaker(bind=engine)
session = Session()
