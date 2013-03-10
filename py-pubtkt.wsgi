import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

# import our Flask app as a WSGI application
from app import app as application
