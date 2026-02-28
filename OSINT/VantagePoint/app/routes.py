from . import app, github, authentik, oauth
from .classes import Tool, Feed, FeedManager, ScanManager, SettingsManager, User, db
from .sec import check_password_complexity, generate_secure_password
from flask import render_template, request, redirect, url_for, flash, session
from flask_login import login_user, logout_user, login_required, current_user
import os
import toons
import re
import pyotp
import qrcode
import io
import base64

@app.before_request
def check_mfa_requirement():
    if current_user.is_authenticated:
        mfa_required = SettingsManager.get_config_value('MFA_REQUIRED', False)
        if mfa_required and not current_user.mfa_enabled:
            # Allow only the MFA setup routes and static files/logout
            allowed_routes = ['mfa_setup', 'mfa_enable', 'logout', 'static']
            if request.endpoint not in allowed_routes:
                flash('Multi-Factor Authentication is required for your account.', 'warning')
                return redirect(url_for('mfa_setup'))

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Check mandatory MFA
        if SettingsManager.get_config_value('MFA_REQUIRED', False) and not current_user.mfa_enabled:
            return redirect(url_for('mfa_setup'))
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if user.mfa_enabled:
                session['mfa_user_id'] = user.id
                return redirect(url_for('mfa_verify'))
            
            login_user(user)
            # Check mandatory MFA right after login
            if SettingsManager.get_config_value('MFA_REQUIRED', False) and not user.mfa_enabled:
                flash('Multi-Factor Authentication is required for this account.', 'success')
                return redirect(url_for('mfa_setup'))
            return redirect(url_for('index'))
        flash('Invalid username or password', 'error')
    
    allow_reg = SettingsManager.get_config_value('ALLOW_USER_REGISTRATION', True)
    return render_template('login.html', github=github, authentik=authentik, allow_registration=allow_reg)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not SettingsManager.get_config_value('ALLOW_USER_REGISTRATION', True):
        flash('User registration is currently disabled by administrator.', 'error')
        return redirect(url_for('login'))
        
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            if not check_password_complexity(password, length_config=SettingsManager.get_config_value('PASSWORD_MIN_LENGTH', 12),
                                             uppercase_config=SettingsManager.get_config_value('PASSWORD_REQUIRE_UPPERCASE', True),
                                             lowercase_config=SettingsManager.get_config_value('PASSWORD_REQUIRE_LOWERCASE', True),
                                             digits_config=SettingsManager.get_config_value('PASSWORD_REQUIRE_NUMBERS', True),
                                             special_config=SettingsManager.get_config_value('PASSWORD_REQUIRE_SYMBOLS', True)):
                flash('Password does not meet complexity requirements.', 'error')
                return redirect(url_for('register'))
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# MFA Routes
@app.route('/mfa/setup')
@login_required
def mfa_setup():
    if current_user.mfa_enabled:
        flash('MFA is already enabled.', 'success')
        return redirect(url_for('settings'))
    
    if not current_user.mfa_secret:
        current_user.mfa_secret = pyotp.random_base32()
        db.session.commit()
        
    totp = pyotp.totp.TOTP(current_user.mfa_secret)
    provisioning_uri = totp.provisioning_uri(name=current_user.username, issuer_name="VantagePoint")
    
    img = qrcode.make(provisioning_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    
    return render_template('mfa_setup.html', qr_code=img_str, secret=current_user.mfa_secret)

@app.route('/mfa/enable', methods=['POST'])
@login_required
def mfa_enable():
    token = request.form.get('token')
    if current_user.verify_totp(token):
        current_user.mfa_enabled = True
        db.session.commit()
        flash('MFA enabled successfully!', 'success')
        return redirect(url_for('settings'))
    flash('Invalid token. Please try again.', 'error')
    return redirect(url_for('mfa_setup'))

@app.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    user_id = session.get('mfa_user_id')
    if not user_id:
        return redirect(url_for('login'))
    
    user = User.query.get(user_id)
    if request.method == 'POST':
        token = request.form.get('token')
        if user.verify_totp(token):
            login_user(user)
            session.pop('mfa_user_id', None)
            return redirect(url_for('index'))
        flash('Invalid token.', 'error')
    return render_template('mfa_verify.html')

# OIDC Routes
@app.route('/login/github')
def github_login():
    if not github:
        flash('GitHub login is not configured.', 'error')
        return redirect(url_for('login'))
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)

@app.route('/login/github/authorize')
def github_authorize():
    if not github:
        return redirect(url_for('login'))
    token = github.authorize_access_token()
    resp = github.get('user', token=token)
    profile = resp.json()
    username = profile.get('login')
    sub = str(profile.get('id'))
    
    user = User.query.filter_by(oidc_sub=sub, oidc_provider='github').first()
    if not user:
        # Check if username exists, if so append github
        if User.query.filter_by(username=username).first():
            username = f"{username}_github"
        user = User(username=username, oidc_sub=sub, oidc_provider='github', email=profile.get('email'))
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    if SettingsManager.get_config_value('MFA_REQUIRED', False) and not user.mfa_enabled:
        flash('Multi-Factor Authentication is required for this account.', 'success')
        return redirect(url_for('mfa_setup'))
    return redirect(url_for('index'))

@app.route('/login/authentik')
def authentik_login():
    if not authentik:
        flash('Authentik login is not configured.', 'error')
        return redirect(url_for('login'))
    redirect_uri = url_for('authentik_authorize', _external=True)
    return authentik.authorize_redirect(redirect_uri)

@app.route('/login/authentik/authorize')
def authentik_authorize():
    if not authentik:
        return redirect(url_for('login'))
    token = authentik.authorize_access_token()
    userinfo = token.get('userinfo')
    sub = userinfo.get('sub')
    username = userinfo.get('preferred_username') or userinfo.get('nickname') or userinfo.get('name')
    
    user = User.query.filter_by(oidc_sub=sub, oidc_provider='authentik').first()
    if not user:
        if User.query.filter_by(username=username).first():
            username = f"{username}_authentik"
        user = User(username=username, oidc_sub=sub, oidc_provider='authentik', email=userinfo.get('email'))
        db.session.add(user)
        db.session.commit()
    
    login_user(user)
    if SettingsManager.get_config_value('MFA_REQUIRED', False) and not user.mfa_enabled:
        flash('Multi-Factor Authentication is required for this account.', 'success')
        return redirect(url_for('mfa_setup'))
    return redirect(url_for('index'))

# Dashboard Routes
@app.route('/')
@login_required
def index():
    tools_list = Tool.get_all_configured_tools()
    # Mock status for UI
    for t in tools_list:
        if not t.enabled:
            t.status = 'Disabled'
        else:
            t.status = 'Active' if (not t.key_required or os.getenv(t.key_env_var)) else 'Missing Key'
    
    feeds = FeedManager.get_all_entries()
    recent_scans = ScanManager.get_recent_scans()
    return render_template('index.html', tools=tools_list, feeds=feeds, recent_scans=recent_scans)

@app.route('/tools', methods=['GET', 'POST'])
@login_required
def tools():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        api_endpoint = request.form.get('api_endpoint')
        author = request.form.get('author', 'Unknown')
        docs_link = request.form.get('docs_link', '')
        key_header_name = request.form.get('key_header_name', 'x-apikey')
        key_required = 'key_required' in request.form
        key_env_var = request.form.get('key_env_var')
        enabled = 'enabled' in request.form
        
        env_config = {
            'IP_SCANNABLE': 'IP_SCANNABLE' in request.form,
            'IP_ROUTE': request.form.get('IP_ROUTE', ''),
            'DOMAIN_SCANNABLE': 'DOMAIN_SCANNABLE' in request.form,
            'DOMAIN_ROUTE': request.form.get('DOMAIN_ROUTE', ''),
            'HASH_SCANNABLE': 'HASH_SCANNABLE' in request.form,
            'HASH_ROUTE': request.form.get('HASH_ROUTE', ''),
            'EMAIL_SCANNABLE': 'EMAIL_SCANNABLE' in request.form,
            'EMAIL_ROUTE': request.form.get('EMAIL_ROUTE', ''),
            'URL_SCANNABLE': 'URL_SCANNABLE' in request.form,
            'URL_ROUTE': request.form.get('URL_ROUTE', '')
        }
        
        new_tool = Tool(name, description, api_endpoint, key_required, key_env_var, env_config, enabled, author, docs_link, key_header_name)
        if new_tool._validate_configuration():
            msg = new_tool.save()
            flash(msg, "success")
        else:
            flash(f"Error adding tool {name}. Missing required details.", "error")
        return redirect(url_for('tools'))

    tools_list = Tool.get_all_configured_tools()
    return render_template('tools.html', tools=tools_list)

@app.route('/tools/delete/<name>')
@login_required
def delete_tool(name):
    if Tool.delete(name):
        flash(f"Module {name} deleted successfully.", "success")
    else:
        flash(f"Error deleting module {name}.", "error")
    return redirect(url_for('tools'))

@app.route('/tools/toggle/<name>')
@login_required
def toggle_tool(name):
    tools_list = Tool.get_all_configured_tools()
    for t in tools_list:
        if t.name == name:
            t.enabled = not t.enabled
            t.save()
            flash(f"Module {name} {'enabled' if t.enabled else 'disabled'}.", "success")
            break
    return redirect(url_for('tools'))

@app.route('/feeds', methods=['GET', 'POST'])
@login_required
def feeds():
    if request.method == 'POST':
        name = request.form.get('name')
        url = request.form.get('url')
        if name and url:
            new_feed = Feed(name, url)
            new_feed.save()
            flash(f"Feed {name} added successfully.", "success")
        return redirect(url_for('feeds'))

    all_feeds = Feed.get_all()
    feed_entries = FeedManager.get_all_entries()
    return render_template('feeds.html', feeds=all_feeds, entries=feed_entries)

@app.route('/feeds/delete/<name>')
@login_required
def delete_feed(name):
    if Feed.delete(name):
        flash(f"Feed {name} deleted successfully.", "success")
    else:
        flash(f"Error deleting feed {name}.", "error")
    return redirect(url_for('feeds'))

@app.route('/feeds/refresh')
@login_required
def refresh_feeds():
    FeedManager.get_all_entries(force_refresh=True)
    flash("Intelligence feeds refreshed.", "success")
    return redirect(url_for('feeds'))

@app.route('/feeds/toggle/<name>')
@login_required
def toggle_feed(name):
    all_feeds = Feed.get_all()
    for f in all_feeds:
        if f.name == name:
            f.enabled = not f.enabled
            f.save()
            flash(f"Feed {name} {'enabled' if f.enabled else 'disabled'}.", "success")
            break
    return redirect(url_for('feeds'))

@app.route('/search', methods=['POST'])
@login_required
def search():
    raw_query = request.form.get('query')
    
    # Refang Defanged Indicators (e.g., hxxp://example[.]com -> http://example.com)
    if raw_query:
        raw_query = raw_query.replace('hxxp', 'http').replace('[.]', '.').replace('[://]', '://').replace('(.)', '.').replace('{.}', '.').replace('[:]', ':')
    
    if not raw_query:
        return redirect(url_for('index'))
    
    # Split query by commas, newlines, or multiple spaces to support bulk
    queries = [q.strip() for q in re.split(r'[\n,\s]+', raw_query) if q.strip()]
    
    if not queries:
        return redirect(url_for('index'))

    tools_list = Tool.get_all_configured_tools()
    bulk_results = {}

    for query in queries:
        results = {}
        for tool in tools_list:
            # search() method handles the scannable and route logic
            res = tool.search(query)
            results[tool.name] = res
        
        bulk_results[query] = results
        # Save each individual scan to history
        ScanManager.save_scan(query, results)
            
    return render_template('results.html', bulk_results=bulk_results)

@app.route('/clear_history')
@login_required
def clear_history():
    ScanManager.clear_history()
    flash("Scan history cleared successfully.", "success")
    return redirect(url_for('index'))

@app.route('/scan/<scan_id>')
@login_required
def view_scan(scan_id):
    scan = ScanManager.get_scan_by_id(scan_id)
    if not scan:
        flash("Scan result not found.", "error")
        return redirect(url_for('index'))
    
    # Format for results.html which expects bulk_results format
    # bulk_results = { query: { tool: data } }
    bulk_results = { scan['query']: scan['full_results'] }
    return render_template('results.html', bulk_results=bulk_results, history_view=True)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'save_app_settings':
            new_settings = {
                'max_scans_retention': request.form.get('max_scans_retention', 50),
                'auto_refresh_feeds': 'auto_refresh_feeds' in request.form,
                'limit_rss_results': request.form.get('limit_rss_results', 25)
            }
            SettingsManager.save_settings(new_settings)
            flash("Application settings updated!", "success")
            
        elif action == 'save_env_vars':
            # Get all keys that look like env vars from the form
            env_updates = {}
            for key in request.form:
                if key not in ['action']:
                    env_updates[key] = request.form.get(key)
            SettingsManager.save_env_vars(env_updates)
            flash("Environment variables updated successfully!", "success")
            
        return redirect(url_for('settings'))
    
    current_settings = SettingsManager.get_settings()
    current_env = SettingsManager.get_env_vars()
    
    # Get all unique env var names required by tools to show them in UI
    tools = Tool.get_all_configured_tools()
    required_keys = sorted(list(set([t.key_env_var for t in tools if t.key_required and t.key_env_var])))
    
    return render_template('settings.html', settings=current_settings, env=current_env, required_keys=required_keys)

@app.route('/about')
def about():
    return render_template('about.html')
