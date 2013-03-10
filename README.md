# Py-PubTkt

A simple Python implementation of the 'login server' for [mod_auth_pubtkt](https://neon1.net/mod_auth_pubtkt/)
which backs onto a Google Apps for Domains account.

### Configuring

* Create a virtualenv: `virtualenv venv`

* Install requirements: `pip install -r requirements.txt`. Note on some Ubuntu releases, you might 
  need to install `python-m2crypto` via apt-get rather than using pip.

* Create some secret keys - the public key needs to go on each host using mod_auth_pubtkt.

    $ openssl genrsa -out privkey.pem 1024
    $ openssl rsa -in privkey.pem -out pubkey.pem -pubout

* Copy `sample.settings.py` to `settings.py` and edit it

* Setup a WSGI host. For [mod_wsgi](https://code.google.com/p/modwsgi/), something like this:

    <VirtualHost *:443>
        ServerName internal.example.com

        # SSL Cert for internal.example.com
        SSLEngine on
        SSLCertificateFile /etc/apache2/ssl/internal-example-com.crt.pem
        SSLCertificateKeyFile /etc/apache2/ssl/internal-example-com.key.pem
        SSLCertificateChainFile /etc/apache2/ssl/internal-example-com.chain.pem
        SSLProtocol all -SSLv2
        SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM

        # Assume code is checked out to /home/sso/py-pubtkt
        WSGIDaemonProcess pubtkt user=sso \
                threads=5 \
                home=/home/sso/py-pubtkt \
                python-path=/home/sso/py-pubtkt/venv/lib/python2.7/site-packages
        WSGIScriptAlias / /home/sso/py-pubtkt/py-pubtkt.wsgi
        <Directory /home/sso/py-pubtkt>
            WSGIProcessGroup pubtkt
            WSGIApplicationGroup %{GLOBAL}
            Order deny,allow
            Allow from all
        </Directory>

        LogLevel info
        CustomLog /var/log/apache2/sso.access.log combined
        ErrorLog /var/log/apache2/sso.error.log
    </VirtualHost>

* On a client app host, configure Apache as per the [mod-auth-pubtkt docs](https://neon1.net/mod_auth_pubtkt/install.html):
  * `TKTAuthPublicKey` should point to the public key you generated above.
  * `TKTAuthLoginURL` should be `https://<url to py-pubtkt>/login` (eg. `https://internal.example.com/login`)
