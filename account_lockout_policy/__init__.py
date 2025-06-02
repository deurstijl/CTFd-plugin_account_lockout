from CTFd.plugins import register_plugin_asset, register_plugin_assets_directory, override_template
from CTFd.plugins import bypass_csrf_protection
from CTFd.utils.decorators import admins_only
from flask import request, Blueprint, jsonify, abort, render_template, url_for, redirect, session
from datetime import datetime, timedelta
import json
from CTFd.utils import get_config, set_config
from CTFd.utils.plugins import register_script as utils_register_plugin_script
from CTFd.utils.user import authed
from CTFd.models import Users, db

from flask import flash

from .models import FailedLogin

def get_policy_config():
    raw = get_config("lockout_policy")
    if raw:
        return json.loads(raw)
    return {
        "enable_lockout_policy": False,
        "failed_logins": 5,
        "lockout_time": 5
    }

def define_docker_admin(app):
    admin_account_lockout_policy = Blueprint('admin_account_lockout_policy', __name__, template_folder='templates',
                                    static_folder='assets')

    @admin_account_lockout_policy.route("/admin/lockout_policy", methods=["GET", "POST"])
    @bypass_csrf_protection
    @admins_only
    def config():
        if request.method == "POST":
            policy = {
                "enable_lockout_policy": 'enable_lockout_policy' in request.form,
                "failed_logins": int(request.form.get('failed_logins', 5)),
                "lockout_time": int(request.form.get('lockout_time', 300))
            }
            set_config("lockout_policy", json.dumps(policy))
            flash("Account lockout policy updated successfully.", "success")
            return redirect(url_for('admin_account_lockout_policy.config'))

        policy = get_policy_config()
        return render_template("lockout_policy_config.html", policy=policy)

    @admin_account_lockout_policy.route("/lockout_policy.json", methods=["GET"])
    def policy_json():
        return jsonify(get_policy_config())

    app.register_blueprint(admin_account_lockout_policy)

    @app.before_request
    def check_lockout():
        # Check if the account is locked-out, if so, redirect to the locked_out page
        if request.endpoint == "auth.login" and request.method == "POST":
            if not get_policy_config()['enable_lockout_policy']:
                return

            username = request.form.get("name")
            user = Users.query.filter_by(name=username).first()

            if user:
                record = FailedLogin.query.filter_by(user_id=user.id).first()
                if record and record.lockout_time and datetime.utcnow() < record.lockout_time:
                    return render_template("locked_out.html",lockouttime=get_policy_config()['lockout_time'])

    @app.after_request
    def track_failed_logins(response):
        if request.endpoint == "auth.login" and request.method == "POST":
            if not get_policy_config()['enable_lockout_policy']:
                return

            username = request.form.get("name")
            user = Users.query.filter_by(name=username).first()

            if  response.status_code == 302 and authed():
                # Successful login, reset failures
                record = FailedLogin.query.filter_by(user_id=user.id).first()
                if record:
                    db.session.delete(record)
                    db.session.commit()
            else:
                # Password is NOT correct
                if user and not authed():
                    record = FailedLogin.query.filter_by(user_id=user.id).first()
                    if not record:
                        record = FailedLogin(user_id=user.id, attempts=1)
                        db.session.add(record)
                    else:
                        record.attempts += 1
                        if record.attempts >= get_policy_config()['failed_logins']:
                            record.lockout_time = datetime.utcnow() + timedelta(minutes=get_policy_config()['lockout_time'])
                    db.session.commit()

        return response

def load(app):
    register_plugin_assets_directory(app, base_path='/plugins/account_lockout_policy/assets')
    app.db.create_all()
    define_docker_admin(app)
    # inject_into_routes(app)