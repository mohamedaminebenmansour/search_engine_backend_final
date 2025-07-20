import os

basedir = os.path.abspath(os.path.dirname(__file__))

SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'users.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
SECRET_KEY = 'votre_clef_secrete_super_secure'
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'mohamedpoly9@gmail.com'
MAIL_PASSWORD = 'qhng eqvq cchg vjcj'