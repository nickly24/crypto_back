"""WSGI entry point for gunicorn etc. Run from inside back/ dir."""
from app import app

application = app
