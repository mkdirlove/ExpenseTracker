import io
import csv
import sqlite3
from flask import g
from flask import Flask, jsonify, render_template, redirect, url_for, request, flash, session, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect here for login

# User class
class User(UserMixin):
    def __init__(self, id, username, password, is_admin=False):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

def enable_foreign_keys(conn):
    """Enable foreign key support in SQLite."""
    conn.execute("PRAGMA foreign_keys = ON;")

# Load user from user ID
@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect('users.db') as conn:
        user_data = conn.execute('SELECT id, username, password, is_admin FROM users WHERE id=?', (user_id,)).fetchone()
        if user_data:
            return User(user_data[0], user_data[1], user_data[2], user_data[3] == 1)  # 1 for admin
    return None

# Create users table
def create_users_table():
    with sqlite3.connect('users.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0
        )''')
create_users_table()

# Create expenses table with a foreign key relationship to users
def create_expenses_table():
    with sqlite3.connect('expenses.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            amount REAL NOT NULL,
            category TEXT NOT NULL,
            date TEXT NOT NULL,
            user_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )''')
create_expenses_table()

def create_initial_admin_user():
    with sqlite3.connect('users.db') as conn:
        # Replace 'admin' and 'admin_password' with desired values
        hashed_password = generate_password_hash('admin')
        try:
            conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                         ('admin', hashed_password, 1))  # Set is_admin to 1 for admin
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # User already exists

create_initial_admin_user()

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('users.db')  # Replace with your database
        g.db.row_factory = sqlite3.Row
    return g.db

def get_user_by_id(user_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return user
@app.route('/')
def index():
    return render_template('index.html')  # Render index.html for logged-in users

@app.route('/dashboard')
@login_required
def dashboard():
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC', (current_user.id,))
        expenses = cursor.fetchall()
    return render_template('dashboard.html', expenses=expenses)

def get_expenses_from_db():
    """Fetches all expenses for the logged-in user."""
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM expenses WHERE user_id=? ORDER BY date DESC', (current_user.id,))
        return cursor.fetchall()

@app.route('/expenses')
@login_required
def expenses():
    search_query = request.args.get('search', '').lower()  # Get search query
    all_expenses = get_expenses_from_db()  # Fetch all user expenses

    # Filter expenses based on the search query (case-insensitive)
    filtered_expenses = [
        expense for expense in all_expenses
        if search_query in expense[1].lower() or search_query in expense[3].lower()
    ]

    return render_template('index.html', expenses=filtered_expenses)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/logout_admin', methods=['POST'])
def logout_admin():
    # Logic to log out the user (e.g., clearing the session)
    session.clear()  # This clears all session data
    return redirect(url_for('login'))  # Redirect to login page or dashboard

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)

        try:
            with sqlite3.connect('users.db') as conn:
                conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, 0)', (username, hashed_password))
                conn.commit()
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(f"Attempting login for: {username}")  # Debugging line

        with sqlite3.connect('users.db') as conn:
            user_data = conn.execute('SELECT id, username, password, is_admin FROM users WHERE username=?',
                                     (username,)).fetchone()

        if user_data:
            print(f"User found: {user_data}")  # Debugging line
            if check_password_hash(user_data[2], password):
                user = User(user_data[0], user_data[1], user_data[2], user_data[3] == 1)
                login_user(user)
                flash('Login successful!', 'success')
                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))  # Redirect admin users to the admin dashboard
                else:
                    return redirect(url_for('dashboard'))  # Regular users to the main dashboard
            else:
                flash('Invalid password!', 'danger')
        else:
            flash('Invalid username!', 'danger')

    return render_template('login.html')

# Route to Analytics Page
@app.route('/analytics')
@login_required
def analytics():
    user_id = current_user.id

    total = get_total_expenses(user_id)
    categories = get_category_expenses(user_id)
    daily_expenses = get_daily_expenses(user_id)
    monthly_expenses = get_monthly_expenses(user_id)
    yearly_expenses = get_yearly_expenses(user_id)

    # Prepare data for the pie chart
    daily_labels = [entry[0] for entry in daily_expenses]  # Get dates
    daily_values = [entry[1] for entry in daily_expenses]  # Get corresponding amounts

    monthly_labels = [entry[0] for entry in monthly_expenses]  # Get months
    monthly_values = [entry[1] for entry in monthly_expenses]  # Get corresponding amounts

    yearly_labels = [entry[0] for entry in yearly_expenses]  # Get years
    yearly_values = [entry[1] for entry in yearly_expenses]  # Get corresponding amounts

    return render_template('analytics.html', total=total, categories=categories,
                           daily_expenses=daily_expenses, monthly_expenses=monthly_expenses,
                           yearly_expenses=yearly_expenses,
                           daily_labels=daily_labels, daily_values=daily_values,
                           monthly_labels=monthly_labels, monthly_values=monthly_values,
                           yearly_labels=yearly_labels, yearly_values=yearly_values)

def get_total_expenses(user_id):
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT SUM(amount) FROM expenses WHERE user_id=?', (user_id,))
        return cursor.fetchone()[0] or 0

def get_category_expenses(user_id):
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT category, SUM(amount) FROM expenses WHERE user_id=? GROUP BY category', (user_id,))
        return cursor.fetchall()

def get_daily_expenses(user_id):
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT date, SUM(amount) FROM expenses WHERE user_id=? GROUP BY date', (user_id,))
        return cursor.fetchall()

def get_monthly_expenses(user_id):
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute(
            'SELECT strftime("%Y-%m", date) AS month, SUM(amount) FROM expenses WHERE user_id=? GROUP BY month',
            (user_id,))
        return cursor.fetchall()

def get_yearly_expenses(user_id):
    with sqlite3.connect('expenses.db') as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT strftime("%Y", date) AS year, SUM(amount) FROM expenses WHERE user_id=? GROUP BY year',
                       (user_id,))
        return cursor.fetchall()

# Route to Add Expense
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():
    if request.method == 'POST':
        title = request.form['title']
        amount = float(request.form['amount'])
        category = request.form['category']
        date = request.form['date']

        with sqlite3.connect('expenses.db') as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO expenses (title, amount, category, date, user_id) VALUES (?, ?, ?, ?, ?)",
                           (title, amount, category, date, current_user.id))
            conn.commit()
        flash('Expense added successfully!', 'success')
        return redirect(url_for('dashboard'))  # Redirect to the dashboard after adding expense
    return render_template('add_expense.html')

@app.route('/edit_expense/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):
    with sqlite3.connect('expenses.db') as conn:
        if request.method == 'POST':
            title = request.form['title']
            amount = float(request.form['amount'])
            category = request.form['category']
            date = request.form['date']
            conn.execute('UPDATE expenses SET title=?, amount=?, category=?, date=? WHERE id=? AND user_id=?',
                         (title, amount, category, date, expense_id, current_user.id))
            conn.commit()
            flash('Expense updated successfully!', 'success')
            return redirect(url_for('dashboard'))

        expense = conn.execute('SELECT * FROM expenses WHERE id=? AND user_id=?',
                               (expense_id, current_user.id)).fetchone()
        if not expense:
            flash('Expense not found or does not belong to you!', 'danger')
            return redirect(url_for('dashboard'))

    return render_template('edit_expense.html', expense=expense)

@app.route('/delete_expense/<int:expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    with sqlite3.connect('expenses.db') as conn:
        conn.execute('DELETE FROM expenses WHERE id=? AND user_id=?', (expense_id, current_user.id))
        conn.commit()
        flash('Expense deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Connect to the users database
    with sqlite3.connect('users.db') as user_conn:
        users = user_conn.execute('SELECT id, username, is_admin FROM users').fetchall()

    # Connect to the expenses database
    with sqlite3.connect('expenses.db') as expense_conn:
        total_expenses = expense_conn.execute('SELECT SUM(amount) FROM expenses').fetchone()[0] or 0
        daily_expenses = expense_conn.execute(
            "SELECT date, SUM(amount) FROM expenses GROUP BY date ORDER BY date DESC LIMIT 7").fetchall()

        # Other analytics data
        monthly_expenses = expense_conn.execute(
            "SELECT strftime('%Y-%m', date) AS month, SUM(amount) FROM expenses GROUP BY month").fetchall()
        yearly_expenses = expense_conn.execute(
            "SELECT strftime('%Y', date) AS year, SUM(amount) FROM expenses GROUP BY year").fetchall()
        categories = expense_conn.execute(
            "SELECT category, SUM(amount) FROM expenses GROUP BY category").fetchall()

    return render_template('admin_dashboard.html', users=users,
                           total_expenses=total_expenses,
                           daily_expenses=daily_expenses,
                           monthly_expenses=monthly_expenses,
                           yearly_expenses=yearly_expenses,
                           categories=categories)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    with sqlite3.connect('users.db') as conn:
        conn.execute('DELETE FROM users WHERE id=?', (user_id,))
        conn.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        is_admin = request.form.get('is_admin', 'off') == 'on'

        try:
            with sqlite3.connect('users.db') as conn:
                conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                             (username, hashed_password, is_admin))
                conn.commit()
                flash('User created successfully!', 'success')
                return redirect(url_for('admin_dashboard'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')

    return render_template('create_user.html')

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = get_user_by_id(user_id)  # Implement this function to fetch user data
    if request.method == 'POST':
        # Get updated data from the form
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('is_admin') == 'on'

        # Logic to update the user in the database
        pass

        return redirect(url_for('admin_dashboard'))

    return render_template('edit_user.html', user=user)  # Pass user data to the template

# Route to Export Expenses
@app.route('/export', methods=['GET'])
@login_required
def export_expenses():
    export_type = request.args.get('type', 'all')  # Default to export all expenses
    output = io.StringIO()
    writer = csv.writer(output)

    if export_type == 'category':
        # Export Category-wise Expenses
        writer.writerow(['Category', 'Total Amount'])
        categories = get_category_expenses(current_user.id)
        for category, total in categories:
            writer.writerow([category, total])
        response_headers = "categories_expenses.csv"
    elif export_type == 'daily':
        # Export Daily Expenses
        writer.writerow(['Date', 'Total Amount'])
        daily_expenses = get_daily_expenses(current_user.id)
        for date, total in daily_expenses:
            writer.writerow([date, total])
        response_headers = "daily_expenses.csv"
    elif export_type == 'monthly':
        # Export Monthly Expenses
        writer.writerow(['Month', 'Total Amount'])
        monthly_expenses = get_monthly_expenses(current_user.id)
        for month, total in monthly_expenses:
            writer.writerow([month, total])
        response_headers = "monthly_expenses.csv"
    elif export_type == 'yearly':
        # Export Yearly Expenses
        writer.writerow(['Year', 'Total Amount'])
        yearly_expenses = get_yearly_expenses(current_user.id)
        for year, total in yearly_expenses:
            writer.writerow([year, total])
        response_headers = "yearly_expenses.csv"
    else:
        # Export All Expenses
        writer.writerow(['Title', 'Amount', 'Category', 'Date'])
        with sqlite3.connect('expenses.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT title, amount, category, date FROM expenses WHERE user_id=?', (current_user.id,))
            expenses = cursor.fetchall()
            for title, amount, category, date in expenses:
                writer.writerow([title, amount, category, date])
        response_headers = "all_expenses.csv"

    output.seek(0)  # Reset StringIO cursor
    return make_response((output.getvalue(), {
        'Content-Type': 'text/csv',
        'Content-Disposition': f'attachment; filename={response_headers}'
    }))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)
