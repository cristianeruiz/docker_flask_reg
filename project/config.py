# project/config.py

import os
basedir = os.path.abspath(os.path.dirname(__file__))


class BaseConfig(object):
    """Base configuration."""
    APP_NAME = 'MINISWIN'
    SECRET_KEY = 'my_precious'
    SECURITY_PASSWORD_SALT = 'my_precious_two'

    DEBUG = False
    BCRYPT_LOG_ROUNDS = 13
    WTF_CSRF_ENABLED = True
    DEBUG_TB_ENABLED = False
    DEBUG_TB_INTERCEPT_REDIRECTS = False
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEBUG = True
    WTF_CSRF_ENABLED = False
    #SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'dev.sqlite')
    #SQLALCHEMY_DATABASE_URI = 'postgresql+psycopg2://flask_user:fl4sk_123@localhost:5432/flask_db'
    SQLALCHEMY_DATABASE_URI = 'postgresql://flask_user:fl4sk_123@localhost:5432/flask_db'
    DEBUG_TB_ENABLED = True

    # mail settings
    #MAIL_SERVER = 'smtp.googlemail.com'
    MAIL_SERVER = 'mail.sistemaspy.com'
    MAIL_PORT = 465
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True

    # mail accounts
    MAIL_DEFAULT_SENDER = 'admin@sistemaspy.com'
    APP_MAIL_USERNAME="admin@sistemaspy.com"
    APP_MAIL_PASSWORD="t9BcKiv;.GbMML"

    # gmail authentication
    MAIL_USERNAME = APP_MAIL_USERNAME
    MAIL_PASSWORD = APP_MAIL_PASSWORD
    #MAIL_USERNAME = os.environ['APP_MAIL_USERNAME']
    #MAIL_PASSWORD = os.environ['APP_MAIL_PASSWORD']

class DevelopmentConfig(BaseConfig):
    """Development configuration."""
    DEBUG = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'dev.sqlite')
    DEBUG_TB_ENABLED = True


class TestingConfig(BaseConfig):
    """Testing configuration."""
    TESTING = True
    DEBUG = True
    BCRYPT_LOG_ROUNDS = 1
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = 'sqlite://'


class ProductionConfig(BaseConfig):
    """Production configuration."""
    SECRET_KEY = 'my_precious'
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = 'postgresql://localhost/example'
    DEBUG_TB_ENABLED = False
    STRIPE_SECRET_KEY = 'foo'
    STRIPE_PUBLISHABLE_KEY = 'bar'
