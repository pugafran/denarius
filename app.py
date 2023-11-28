from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from datetime import datetime



app = Flask(__name__)

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///denarius.sqlite'
app.config['SECRET_KEY'] = 'mamahuevo'

db = SQLAlchemy(app)



login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Después de inicializar tu aplicación y db
migrate = Migrate(app, db)




class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(255))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Modelo de usuario
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    mail = db.Column(db.String(100), unique=True)
    incomes = db.relationship('Income', backref='user', lazy=True)
    expenses = db.relationship('Expense', backref='user', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Ruta de inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user is None or not check_password_hash(user.password, password):
            error = 'Usuario o contraseña inválidos'
        else:
            login_user(user)
            return redirect(url_for('secret_page'))

    return render_template('login.html', error=error)

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        mail = request.form.get('mail')
        password = request.form.get('password')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, mail=mail)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')

# Ruta de gastos
@app.route('/add_income', methods=['POST'])
@login_required
def add_income():
    try:
        amount = float(request.form.get('amount'))
        description = request.form.get('description')
        date_str = request.form.get('date')
        date = datetime.strptime(date_str, '%Y-%m-%d') if date_str else datetime.utcnow()

        new_income = Income(amount=amount, description=description, date=date, user_id=current_user.id)
        db.session.add(new_income)
        db.session.commit()
    except (TypeError, ValueError):
        # Manejar el error, por ejemplo, mostrando un mensaje al usuario
        pass

    return redirect(url_for('secret_page'))



@app.route('/add_expense', methods=['POST'])
@login_required
def add_expense():
    amount = float(request.form.get('amount'))
    description = request.form.get('description')
    date_str = request.form.get('date')
    date = datetime.strptime(date_str, '%Y-%m-%d')

    new_expense = Expense(amount=amount, description=description, date=date, user_id=current_user.id)
    db.session.add(new_expense)
    db.session.commit()

    return redirect(url_for('secret_page'))



# Ruta de transacciones
@app.route('/view_transactions', methods=['GET'])
@login_required
def view_transactions():
    date = request.args.get('date')
    selected_date = datetime.strptime(date, '%Y-%m-%d')

    incomes = Income.query.filter_by(user_id=current_user.id, date=selected_date).all()
    expenses = Expense.query.filter_by(user_id=current_user.id, date=selected_date).all()

    return render_template('view_transactions.html', incomes=incomes, expenses=expenses, date=selected_date)



# Ruta de cierre de sesión
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Ruta protegida
@app.route('/secret')
@login_required
def secret_page():
    user_incomes = Income.query.filter_by(user_id=current_user.id).all()
    user_expenses = Expense.query.filter_by(user_id=current_user.id).all()

    return render_template('secret_page.html', incomes=user_incomes, expenses=user_expenses, user=current_user)



# Ruta principal
@app.route('/')
def index():
    return 'Inicio - <a href="/login">Iniciar sesión</a> | <a href="/register">Registrarse</a>'

# Ejemplo: Eliminar todos los usuarios



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
