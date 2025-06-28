import os
from decimal import Decimal, ROUND_HALF_UP

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import requests

from helpers import apology, login_required, lookup, usd

# --- SECURITY SETTINGS ---
from flask_wtf import CSRFProtect

# Configure application
app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = False  
app.config['PERMANENT_SESSION_LIFETIME'] = 2592000  

# CSRF Protection
csrf = CSRFProtect(app)

# Custom filter
app.jinja_env.filters["usd"] = usd

app.config["SESSION_PERMANENT"] = True  # Enable permanent sessions
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# --- WATCHLIST TABLE CREATION (run once) ---
import sqlite3
with sqlite3.connect('finance.db') as conn:
    conn.execute('''CREATE TABLE IF NOT EXISTS watchlist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        symbol TEXT NOT NULL
    );''')

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
def index():
    """Show portfolio of stocks"""
    # Check if user is logged in
    if "user_id" not in session:
        return redirect("/login")
    
    user_id = session["user_id"]

    transactions = db.execute(
        "SELECT symbol, name, SUM(shares) AS shares, price FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0;",user_id)
    cash = db.execute("SELECT cash FROM users WHERE id = (?);" , user_id)

    totalcash = Decimal(str(cash[0]["cash"]))
    sum = totalcash

    for row in transactions:
        look = lookup(row["symbol"])
        if look is not None:
            row["price"] = Decimal(str(look["price"]))
            row["total"] = (row["price"] * row["shares"]).quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)
            sum += row["total"]
        else:
            # Handle case where lookup fails
            row["price"] = Decimal('0.00')
            row["total"] = Decimal('0.00')
            flash(f"Unable to get current price for {row['symbol']}")

    sum = sum.quantize(Decimal('0.01'), rounding=ROUND_HALF_UP)

    return render_template("index.html", database=transactions, users=cash, sum=sum)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        buy = lookup(request.form.get("symbol"))

        if buy == None:
            return apology("Invalid Symbol")

        user_id = session["user_id"]
        name = buy["name"]
        price = buy["price"]
        shares =  request.form.get("shares")
        symbol =  request.form.get("symbol")

        if not shares.isdigit():
            return apology("You can't purchase partial shares.")
        shares = int(shares)
        if shares <= 0:
            return apology("Invalid share amount.")

        cash_db = db.execute("SELECT cash FROM users WHERE id = (?);", user_id)
        user_cash = cash_db[0]["cash"]
        purchase = price * shares
        update_user_cash = user_cash - purchase

        if user_cash < purchase:
            return apology("Funds not sufficient.")

        db.execute("UPDATE users SET cash = (?) WHERE id = (?);", update_user_cash, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price) VALUES (?, ?, ?, ?, ?)", user_id, symbol, name, shares, price)
        flash("Bought!")
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT symbol, name, shares, price FROM transactions WHERE user_id = (?);", user_id)

    buy_sell = []
    for row in transactions:
        if row["shares"] <= 0:
            row["buy_sell"] = "SELL"
        else:
            row["buy_sell"] = "BUY"

    return render_template("history.html", database=transactions, buy_sell=buy_sell)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        
        # Make session permanent only if "Remember Me" is checked
        if request.form.get("remember"):
            session.permanent = True

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
@csrf.exempt
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        
        # Validate symbol
        if not symbol or not symbol.strip():
            return apology("Please provide a valid stock symbol.")
        
        quoted = lookup(symbol.strip())

        if quoted == None:
            return apology("Quote symbol doesn't exist.")

        return render_template("quoted.html", quoted=quoted)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if request.method == "POST":
        #ensuring username submitted
        if not username:
            return apology("Username Mandatory.",400)

        #ensuring password submitted
        elif not password:
            return apology("Password Mandatory.",400)

        elif password != confirmation:
            return apology("Passwords do not match.",400)

        #database query for username
        try:
            db.execute("INSERT INTO users (username, hash, cash) VALUES (?, ?, 10000.00);", username, generate_password_hash(password))
        except:
            return apology("Username already taken, please enter another username",400)

        flash("Registered Successfully")

        # Log the user in automatically after registration
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        
        # Make session permanent only if "Remember Me" is checked
        if request.form.get("remember"):
            session.permanent = True

        #Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]

    if request.method == "GET":
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = (?) GROUP BY symbol HAVING SUM(shares) > 0;", user_id)
        return render_template("sell.html", symbol=symbols)

    elif request.method == "POST":
        sell = lookup(request.form.get("symbol"))
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        name = sell["name"]
        price = sell["price"]

        if shares <= 0:
            return apology("Share amount not allowed")

        if symbol == None:
            return apology("Invalid Symbol")

        cash_db = db.execute("SELECT cash FROM users WHERE id = (?);", user_id)
        user_cash = int(cash_db[0]["cash"])

        oldshares = db.execute("SELECT SUM(shares) AS shares FROM transactions WHERE user_id = (?) AND symbol = (?);", user_id, symbol)
        no_old_shares = int(oldshares[0]["shares"]) if oldshares[0]["shares"] else 0

        if shares > no_old_shares:
            return apology("Insufficient share units in your account")

        sold = price * shares
        update_user_cash = user_cash + sold

        db.execute("UPDATE users SET cash = (?) WHERE id = (?);", update_user_cash, user_id)
        db.execute("INSERT INTO transactions (user_id, symbol, name, shares, price) VALUES (?, ?, ?, ?, ?)",
                   user_id, symbol, name, shares*(-1), price)

        flash("Sold!")
        return redirect("/")

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def change_password():
    user_id = session["user_id"]
    password = request.form.get("password")
    newpassword = request.form.get("newpassword")
    confirmation = request.form.get("confirmation")

    if request.method == "POST":
        if not password:
            return apology("Must provide password", 400)
        elif not newpassword:
            return apology("Must provide new password", 400)
        elif newpassword != confirmation:
            return apology("Password do not match!", 400)
        rows = db.execute("SELECT * FROM users WHERE id = ?", user_id)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return apology("Password incorrect!", 403)
        try:
            db.execute("UPDATE users SET hash = (?) WHERE id = (?);", generate_password_hash(newpassword), user_id)
        except:
            return apology("Please try again", 400)
        flash("Password change Successful!")
        return redirect("/")
    else:
        return render_template("changepassword.html")



@app.route('/api/portfolio_history')
@login_required
def portfolio_history():
    user_id = session["user_id"]
    # Get all transactions for the user, ordered by timestamp
    txs = db.execute("SELECT timestamp, symbol, shares, price FROM transactions WHERE user_id = ? ORDER BY timestamp", user_id)
    # Get initial cash
    cash_rows = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    if not cash_rows:
        return jsonify([])
    initial_cash = 10000.0  # Default for CS50 finance
    # Reconstruct portfolio value over time
    history = []
    holdings = {}
    cash = initial_cash
    
    # Group transactions by date to reduce API calls
    date_transactions = {}
    for tx in txs:
        date = tx["timestamp"].split()[0]
        if date not in date_transactions:
            date_transactions[date] = []
        date_transactions[date].append(tx)
    
    for date, day_txs in date_transactions.items():
        # Process all transactions for this date
        for tx in day_txs:
            symbol = tx["symbol"]
            shares = tx["shares"]
            price = tx["price"]
            cash -= price * shares
            holdings[symbol] = holdings.get(symbol, 0) + shares
        
        # Calculate value at this point (only once per date)
        total = cash
        for sym, sh in holdings.items():
            if sh > 0:
                try:
                    look = lookup(sym)
                    if look is not None:
                        total += look["price"] * sh
                except Exception:
                    # Skip failed lookups to avoid slowing down the graph
                    continue
        history.append({"date": date, "value": round(total, 2)})
    
    return jsonify(history)

@app.route('/api/holdings_pie')
@login_required
def holdings_pie():
    user_id = session["user_id"]
    # Get all holdings for the user
    rows = db.execute("SELECT symbol, SUM(shares) as shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
    data = []
    for row in rows:
        look = lookup(row["symbol"])
        if look is not None:
            value = look["price"] * row["shares"]
            data.append({"symbol": row["symbol"], "value": round(value, 2)})
    return jsonify(data)

@app.route('/api/news')
@login_required
def api_news():
    # Use Finnhub for headlines
    API_KEY = os.environ.get('FINNHUB_API_KEY', 'demo')  # Get from environment variable
    try:
        r = requests.get(f'https://finnhub.io/api/v1/news?category=general&token={API_KEY}')
        news = r.json()[:10]
        return jsonify(news)
    except Exception as e:
        return jsonify([])

@app.route('/api/autocomplete')
@login_required
def api_autocomplete():
    query = request.args.get('q', '')
    if not query:
        return jsonify([])
    API_KEY = os.environ.get('FINNHUB_API_KEY', 'demo')  
    try:
        r = requests.get(f'https://finnhub.io/api/v1/search?q={query}&token={API_KEY}')
        data = r.json()
        matches = data.get('result', []) if isinstance(data, dict) else []
    except Exception:
        matches = []
    results = [{
        'symbol': m['symbol'],
        'name': m['description']
    } for m in matches]
    return jsonify(results)

@app.route('/watchlist', methods=['GET', 'POST', 'DELETE'])
@login_required
@csrf.exempt
def watchlist():
    user_id = session['user_id']
    if request.method == 'GET':
        rows = db.execute('SELECT symbol FROM watchlist WHERE user_id = ?', user_id)
        symbols = [row['symbol'] for row in rows]
        print(f"User {user_id} watchlist: {symbols}")  # Debug print
        return jsonify(symbols)
    elif request.method == 'POST':
        symbol = request.json.get('symbol')
        if not symbol:
            return apology('No symbol provided')
        print(f"Adding {symbol} to user {user_id} watchlist")  # Debug print
        db.execute('INSERT INTO watchlist (user_id, symbol) VALUES (?, ?)', user_id, symbol)
        return jsonify({'success': True})
    elif request.method == 'DELETE':
        symbol = request.json.get('symbol')
        print(f"Removing {symbol} from user {user_id} watchlist")  # Debug print
        db.execute('DELETE FROM watchlist WHERE user_id = ? AND symbol = ?', user_id, symbol)
        return jsonify({'success': True})

@app.route('/api/config')
@login_required
def api_config():
    """Return configuration data for frontend"""
    return jsonify({
        'finnhub_api_key': os.environ.get('FINNHUB_API_KEY', 'demo')
    })
