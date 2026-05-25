import os
import json
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnerability.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    id = db.Column(db.String(255), primary_key=True)
    title = db.Column(db.String(255))
    cve = db.Column(db.String(50))
    severity = db.Column(db.String(50))
    publish_date = db.Column(db.String(50))
    year = db.Column(db.Integer)
    vuln_type = db.Column(db.String(50))
    description = db.Column(db.Text)
    solution = db.Column(db.Text)
    references_json = db.Column(db.Text)
    cvss = db.Column(db.String(50))
    last_updated = db.Column(db.String(50))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # Get filters
    year_filter = request.args.get('year', type=int)
    type_filter = request.args.get('type')
    severity_filter = request.args.get('severity')
    search_query = request.args.get('q')

    query = Vulnerability.query

    if year_filter:
        query = query.filter(Vulnerability.year == year_filter)
    if type_filter:
        query = query.filter(Vulnerability.vuln_type == type_filter)
    if severity_filter:
        query = query.filter(Vulnerability.severity.ilike(f'%{severity_filter}%'))
    if search_query:
        query = query.filter(
            (Vulnerability.title.ilike(f'%{search_query}%')) | 
            (Vulnerability.cve.ilike(f'%{search_query}%')) |
            (Vulnerability.description.ilike(f'%{search_query}%'))
        )

    # Stats for sidebar/filters
    years = db.session.query(Vulnerability.year).distinct().order_by(Vulnerability.year.desc()).all()
    types = db.session.query(Vulnerability.vuln_type).distinct().all()
    
    vulns = query.order_by(Vulnerability.publish_date.desc()).all()
    
    return render_template('index.html', 
                         vulnerabilities=vulns, 
                         years=[y[0] for y in years], 
                         types=[t[0] for t in types])

@app.route('/vuln/<path:vuln_id>')
@login_required
def detail(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    references = json.loads(vuln.references_json) if vuln.references_json else []
    return render_template('detail.html', vuln=vuln, references=references)

# Command to create admin user
@app.cli.command("create-admin")
def create_admin():
    username = input("Enter username: ")
    password = input("Enter password: ")
    user = User(username=username, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()
    print(f"Admin user {username} created.")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
