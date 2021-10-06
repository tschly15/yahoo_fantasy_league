#!/usr/bin/env python

from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import timedelta

from config import Config


app = Flask(__name__)
app.config.from_object(Config)

#provide maximum session duration
app.permanent_session_lifetime = timedelta(minutes=5)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'


from app import routes, models

#app.run(debug=True, ssl_context='adhoc', port=app.port)


# Thank you Miguel G
