from flask import Flask
from dotenv import load_dotenv
import os
import toons
from flask_login import LoginManager
from authlib.integrations.flask_client import OAuth

load_dotenv()

CONFIG_PATH = os.getenv('CONFIG_PATH', 'vantage.conf')

try:
    with open(CONFIG_PATH, 'r') as config_file:
        config_data = config_file.read()
        print(f"Configuration loaded from {CONFIG_PATH}")
except FileNotFoundError:
    print(f"Configuration file {CONFIG_PATH} not found. Using default settings.")

# Ensure modules directory exists
if not os.path.exists('app/toolkit/modules'):
    os.makedirs('app/toolkit/modules', exist_ok=True)

if not os.path.exists('app/cache/scans'):
    os.makedirs('app/cache/scans', exist_ok=True)

from .classes import Tool, db, User
# Tool.setup_defaults() # Moved below db creation

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key')

# Use absolute path for DB in project root
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(os.path.dirname(basedir), 'vantage.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

oauth = OAuth(app)

# GitHub OIDC
github_id = os.getenv('GITHUB_CLIENT_ID')
github_secret = os.getenv('GITHUB_CLIENT_SECRET')
if github_id and github_secret:
    github = oauth.register(
        name='github',
        client_id=github_id,
        client_secret=github_secret,
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )
else:
    github = None

# Authentik OIDC
authentik_id = os.getenv('AUTHENTIK_CLIENT_ID')
authentik_secret = os.getenv('AUTHENTIK_CLIENT_SECRET')
authentik_url = os.getenv('AUTHENTIK_ISSUER_URL')
if authentik_id and authentik_secret and authentik_url:
    authentik = oauth.register(
        name='authentik',
        client_id=authentik_id,
        client_secret=authentik_secret,
        server_metadata_url=authentik_url.rstrip('/') + '/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid profile email'},
    )
else:
    authentik = None

with app.app_context():
    db.create_all()
    Tool.setup_defaults()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from . import routes