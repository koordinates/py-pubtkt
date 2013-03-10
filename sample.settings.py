# You must configure these 3 values from Google APIs console
# https://code.google.com/apis/console
GOOGLE_CLIENT_ID = ""
GOOGLE_CLIENT_SECRET = ""
# the local path for the redirect URL you set in the APIs Console
GOOGLE_REDIRECT_URI = "/oauth2callback"
# Restrict logins to users from this GApps domain
GOOGLE_DOMAIN_CHECK = "example.com"

# Domain to set cookies against
TKT_DOMAIN = ".internal.example.com"
TKT_COOKIE = "auth_pubtkt"  # default
TKT_EXPIRY = 86400  # 1 day
# See the mod_auth_pubtkt docs to generate a keypair
TKT_PRIVATE_KEY = "/path/to/mod_auth_pubtkt/keys/privkey.pem"
TKT_PUBLIC_KEY = "/path/to/mod_auth_pubtkt/keys/pubkey.pem"
# Restrict cookies to only go via HTTPS
TKT_SSL_ONLY = False
# Set Client IPs in cookie values
TKT_CLIENT_IP = False

# A LONG and RANDOM string
SECRET_KEY = "developer key"
# Print lots of noise (SECURITY-SENSITIVE) to stderr
DEBUG = True

# Name to put at the top of the pages
APP_NAME = "Example Co"
# Application link/launch list
APP_LIST = (
    ("My App 1", "https://myapp1.internal.example.com/"),
    ("My App 2", "https://myapp1.internal.example.com/"),
)
