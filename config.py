import misc

class Config(object):
        PORT = 5000
        SECRET_KEY = misc.SECRET_KEY

        SQLALCHEMY_TRACK_MODIFICATIONS = False
        SQLALCHEMY_DATABASE_URI = misc.DATABASE_URL
