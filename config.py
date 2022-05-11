import os
import string

from decouple import config


BASE_DIR = os.path.abspath('.')

DEBUG = config('DEBUG', cast=bool)

#SECRET_KEY = config('SECRET_KEY') or \
#    ''.join(random.choice(string.ascii_letters) for i in range(42))