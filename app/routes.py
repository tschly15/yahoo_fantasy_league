#!/usr/bin/env python
from oauthlib.oauth2 import WebApplicationClient
from flask_login import current_user, login_user, logout_user, login_required
from flask import redirect, request, url_for, session, render_template, flash, make_response
from werkzeug.urls import url_parse

from app import app, db
from app.models import FantasyUser
from app.forms import LoginForm, RegistrationForm


@app.route('/')
@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():

        user = FantasyUser.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))

        login_user(user, remember=form.remember_me.data)

        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)

    return render_template('login.html', title='Sign In', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/index', methods=['GET'])
def index():
    if current_user.is_authenticated:
        return "hello, you are authenticated {0}".format(current_user.username)

    response = make_response(redirect(url_for('login')))
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = FantasyUser(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/home', methods=['GET','POST'])
def home():

    if request.method == 'GET':
        for key in session.keys():
            del session[key]
        return render_template('home.html')

    if 'user_id' in request.form:
        user_id = request.form['user_id']
        try:
            #retrieve user data from the database
            session['user'] = FantasyUser.get_user(user_id).to_json()
        except KeyError:
            #create new user and then serialize w/in session
            session['user'] = FantasyUser(user_id).to_json()
            return render_template('home.html', session=session, user_id=user_id)
        else:
            return redirect(url_for('leaguer'))

    user = FantasyUser(load_web_user=session['user'])
    user.league_id = request.form['league_id']
    session['user'] = user.to_json()

    return redirect(url_for('request_auth'))

@app.route('/request_auth', methods=['GET'])
def request_auth():
    '''
    Request an authorization URL
     Send: client_id, redirect_uri, response_type
     Receive: authorization code
    '''

    user = FantasyUser(load_web_user=session['user'])
    league_obj = league(user.league_id)

    client = WebApplicationClient(league_obj.client_id)
    req = client.prepare_authorization_request(
            league.request_auth_url,
            redirect_url = league_obj.redirect_url)

    auth_url, headers, body = req
    return redirect(auth_url)

@app.route('/callback', methods=['GET','POST'])
def callback():
    '''
    Exchange authorization code for access token
     Send: client_id, client_secret, redirect_uricode, grant_type
     Receive: access_token, token_type, expire_in, refresh_token, xoauth_yahoo_guid
    '''

    user = FantasyUser(load_web_user=session['user'])
    league_obj = league(user.league_id)

    client = WebApplicationClient(league_obj.client_id)
    req = client.prepare_token_request(
            league.request_token_url,
            authorization_response=request.url,
            redirect_url = league_obj.redirect_url,
            client_secret = league_obj.client_secret)

    token_url, headers, body = req
    resp = requests.post(token_url, headers=headers, data=body)

    #store the oauth credentials w/in our user
    user.set_tokens(resp.json())
    user.persist_user()
    session['user'] = user.to_json()

    return redirect(url_for('leaguer'))

@app.route('/refresh', methods=['GET','POST'])
def refresh():
    '''
    Exchange refresh token for a new access token
     Send: client_id, client_secret, redirect_uri, refresh_token, grant_type
     Receive: access_token, token_type, expire_in, refresh_token, xoauth_yahoo_guid
    Note: only the access_token will change (refresh_token does not change)
    '''

    user = FantasyUser(load_web_user=session['user'])
    league_obj = league(user.league_id)

    client = WebApplicationClient(league_obj.client_id)
    req = client.prepare_refresh_token_request(
        league.request_token_url,
        refresh_token = user.refresh_token,
        client_id = league_obj.client_id,
        client_secret = league_obj.client_secret,
        redirect_uri = league_obj.redirect_url)

    token_url, headers, body = req
    resp = requests.post(token_url, headers=headers, data=body) 

    #store the oauth credentials w/in our user
    user.set_tokens(resp.json())
    user.persist_user()
    session['user'] = user.to_json()

    return redirect(url_for('leaguer'))

@app.route('/leaguer', methods=['GET','POST'])
def leaguer():

    user = FantasyUser(load_web_user=session['user'])
    league_obj = league(user.league_id)

    payload = {
        'use_login': '1',
        'format': 'json',
        'access_token': user.access_token,
    }
    players_url = '{0}/league/{1}.l.{2}/players'.format(league.v2_url, '390', user.league_id)

    start = 0
    count_per = 25
    status_code = 200

    while status_code == 200:

        url = '{0};count={1};start={2}'.format(players_url, count_per, start)
        resp = requests.get(url.format(start), params=payload)

        #received an Unauthorized response
        if resp.status_code == 401:
            refresh() #renew our credentials

            user = FantasyUser(load_web_user=session['user'])
            status_code = 200
            payload['access_token'] = user.access_token
            continue

        dct = resp.json()['fantasy_content']
        for key, entry in dct.iteritems():
            print(key, entry)

        try:
            with open('output.json','a') as f:
                f.write(json.dumps(dct, indent=2))
        except Exception as e:
            print('failed to create the output file:',e.args)

        status_code = resp.status_code
        raw_input((start, status_code))
        start += count_per
