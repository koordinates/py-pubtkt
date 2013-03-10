#!/usr/bin/env python

import json
import time
import base64
import urllib
import sys

from flask import Flask, redirect, url_for, session, request, \
    flash, render_template
from flask_oauth import OAuth
import httplib2
import M2Crypto

import settings


app = Flask(__name__)
app.secret_key = settings.SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = settings.TKT_SSL_ONLY
app.debug = settings.DEBUG


google = OAuth().remote_app('google',
                            base_url='https://www.google.com/accounts/',
                            authorize_url='https://accounts.google.com/o/oauth2/auth',
                            request_token_url=None,
                            request_token_params={
                                'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
                                'response_type': 'code',
                                'hd': settings.GOOGLE_DOMAIN_CHECK,
                            },
                            access_token_url='https://accounts.google.com/o/oauth2/token',
                            access_token_method='POST',
                            access_token_params={
                                'grant_type': 'authorization_code',
                            },
                            consumer_key=settings.GOOGLE_CLIENT_ID,
                            consumer_secret=settings.GOOGLE_CLIENT_SECRET)


class PubTkt(object):
    class BadSignature(Exception):
        pass

    def __init__(self, private_key, public_key, expiry=86400, uid_field='email', use_cip=False):
        self.private_key = private_key
        self.public_key = public_key
        self.expiry = expiry
        self.use_cip = use_cip
        self.uid_field = uid_field

    def get_tokens(self, user_info, request):
        return None

    def get_uid(self, user_info, request):
        return user_info[self.uid_field]

    def get_validuntil(self, user_info, request):
        return int(time.time() + self.expiry)

    def get_cip(self, user_info, request):
        if self.use_cip:
            return request.remote_addr
        else:
            return None

    def get_udata(self, user_info, request):
        data = {
            'name': user_info['name'],
        }
        return json.dumps(data, separators=(',', ':'))

    def get_graceperiod(self, user_info, request):
        return None

    def get_bauth(self, user_info, request):
        return None

    def sign(self, ticket):
        privkey = M2Crypto.EVP.load_key(self.private_key)
        privkey.reset_context('sha1')
        privkey.sign_init()
        privkey.sign_update(ticket)
        sig = privkey.sign_final()
        return base64.b64encode(sig)

    def verify(self, ticket, sig):
        sig = base64.b64decode(sig)
        rsa = M2Crypto.RSA.load_pub_key(self.public_key)
        pubkey = M2Crypto.EVP.PKey()
        pubkey.assign_rsa(rsa)
        pubkey.reset_context('sha1')
        pubkey.verify_init()
        pubkey.verify_update(ticket)
        return pubkey.verify_final(sig)

    def make_cookie(self, user_info, request):
        data = []
        for field in ('uid', 'validuntil', 'cip', 'tokens', 'udata', 'graceperiod', 'bauth'):
            value = getattr(self, 'get_' + field)(user_info, request)
            if value is not None:
                data.append('%s=%s' % (field, value))
            elif field in ('uid', 'validuntil'):
                raise ValueError("Field %s can't be None" % field)

        ticket = u';'.join(data).encode('utf-8')
        ticket += ';sig=' + self.sign(ticket)
        return ticket

    def check_cookie(self, cookie, request):
        try:
            cookie = cookie.encode('utf-8')  # make it back into a string for now
            a, b = cookie.rsplit(';', 1)
            k, sig = b.split('=', 1)
            if k != 'sig':
                raise self.BadSignature("Sig missing")

            if self.verify(a, sig) <= 0:
                raise self.BadSignature("Sig mismatch")

            data = {}
            for p in cookie.split(';'):
                k, v = p.split('=', 1)
                data[k] = v.decode('utf-8')

            if not set(data.keys()) >= set(('uid', 'validuntil')):
                raise self.BadSignature("Missing fields")

            if not data['validuntil'].isdigit():
                raise self.BadSignature("validuntil non-numeric")

            if 'udata' in data:
                data['udata'] = json.loads(data['udata'])

        except self.BadSignature, e:
            raise
        except Exception, e:
            raise self.BadSignature(e)

        if self.use_cip and 'cip' in data:
            if data['cip'] != request.remote_addr:
                raise self.BadSignature("CIP")

        if time.time() > int(data['validuntil']):
            raise self.BadSignature("Expired")

        return data


def get_user_info(access_token):
    h = httplib2.Http()
    headers = {
        'Authorization': 'OAuth ' + access_token
    }
    resp, content = h.request('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)
    return json.loads(content)


@app.route('/')
def index():
    context = {
        'APP_LIST': settings.APP_LIST,
        'APP_NAME': settings.APP_NAME,
    }

    if settings.TKT_COOKIE in request.cookies:
        tkt = PubTkt(private_key=settings.TKT_PRIVATE_KEY, public_key=settings.TKT_PUBLIC_KEY)
        cookie_value = urllib.unquote_plus(request.cookies[settings.TKT_COOKIE])

        try:
            data = tkt.check_cookie(cookie_value, request)
            return render_template('index.html',
                                   user_info=data['udata'], uid=data['uid'],
                                   **context)
        except tkt.BadSignature, e:
            #Unauthorized - bad token
            print >>sys.stderr, "Bad signature!", e, cookie_value
            flash("Bad signature - log out?", "error")

    return render_template('index.html', **context)


@app.route('/login')
def login():
    # TODO: XSRF prevention
    callback = url_for('oauth2callback', _external=True)
    resp = google.authorize(callback=callback)
    session['login_redirect'] = request.args.get('back', url_for('index'))
    return resp


@app.route('/logout')
def logout():
    flash('You were successfully logged out', 'success')
    r = redirect(url_for('index'))
    # clear the cookie
    r.set_cookie(settings.TKT_COOKIE, '', expires=0, domain=settings.TKT_DOMAIN)
    return r


@app.route(settings.GOOGLE_REDIRECT_URI)
@google.authorized_handler
def oauth2callback(resp):
    try:
        # TODO: XSRF prevention from /login
        user_info = get_user_info(resp['access_token'])
        if user_info['hd'] != settings.GOOGLE_DOMAIN_CHECK or not user_info['email'].endswith('@' + settings.GOOGLE_DOMAIN_CHECK):
            print >>sys.stderr, "Domain check failed: ", user_info['hd'], user_info['email']
            flash("Your Google domain doesn't match", 'error')
            return redirect(url_for('index'))

        tkt = PubTkt(private_key=settings.TKT_PRIVATE_KEY, public_key=settings.TKT_PUBLIC_KEY, expiry=settings.TKT_EXPIRY, use_cip=settings.TKT_CLIENT_IP)

        ticket = tkt.make_cookie(user_info, request)
        cookie_value = urllib.quote_plus(ticket)
        if settings.DEBUG:
            print >>sys.stderr, "DEBUG: new ticket:", ticket
            print >>sys.stderr, "DEBUG: new cookie:", "%s=%s" % (settings.TKT_COOKIE, cookie_value)

        r = redirect(session.get('login_redirect', '') or '/')
        r.set_cookie(settings.TKT_COOKIE, cookie_value, httponly=True, max_age=settings.TKT_EXPIRY-1, path='/', domain=settings.TKT_DOMAIN, secure=settings.TKT_SSL_ONLY)
        return r
    except Exception, e:
        print >>sys.stderr, "oauth2callback error: ", e
        flash('Error setting up your session... try again?', 'error')


if __name__ == '__main__':
    if len(sys.argv) == 1:
        app.run(host='0.0.0.0', port=5000)
    else:
        # given some ticket data, sign and re-verify it
        # eg. ./app.py "uid=mkasper;cip=192.168.200.163;validuntil=1201383542;tokens=foo,bar;udata=mydata"
        tkt = PubTkt(private_key=settings.TKT_PRIVATE_KEY, public_key=settings.TKT_PUBLIC_KEY, expiry=settings.TKT_EXPIRY, use_cip=settings.TKT_CLIENT_IP)
        ticket = sys.argv[1]
        print "TICKET:", ticket
        sig = tkt.sign(ticket)
        print "SIG:", sig
        print "COOKIE: %s=%s" % (settings.TKT_COOKIE, urllib.quote_plus(ticket + ";sig=" + sig))
        print "VERIFY:", tkt.verify(ticket, sig)
