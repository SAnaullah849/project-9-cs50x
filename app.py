import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request,session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    id = session["user_id"]

    # Get user cash
    cash_db = db.execute("SELECT cash FROM users WHERE id=?", id)
    cash = cash_db[0]["cash"]

    # Get user transactions and aggregate shares
    transactions_db = db.execute(
        "SELECT symbol, SUM(shares) AS shares FROM transactions WHERE user_id=? GROUP BY symbol", id
    )

    # Prepare portfolio data
    portfolio = []
    total_value = cash

    for transaction in transactions_db:
        symbol = transaction["symbol"]
        shares = transaction["shares"]


        if shares > 0:
            quote = lookup(symbol)
            if quote:
                price = quote["price"]
                total = price * shares
                portfolio.append({
                    "symbol": symbol,
                    "shares": shares,
                    "price": price,
                    "total": total
                })
                total_value += total

    return render_template("index.html", portfolio=portfolio, cash=cash, total_value=total_value)



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol=request.form.get("symbol")
        shares=request.form.get("shares")
        try:
            shares =int(shares)
        except ValueError:
            return apology("shares must be an integer", 400)

        if not symbol:
            return apology("MUST GIVE SYMBOL",400)
        stock=lookup(symbol.upper())
        if stock == None :
            return apology("symbol does not Exist",400)
        if shares < 0 :
            return apology("Share Not Allowed",400)

        if shares <= 0:
            return apology("shares must be positive", 400)
        if stock is None:
            return apology("invalid symbol", 400)
        transaction_value=shares * stock["price"]
        user_id =session["user_id"]
        user_cash_db=db.execute("SELECT cash FROM users WHERE id=:id",id=user_id)
        user_cash=user_cash_db[0]["cash"]

        if user_cash < transaction_value:
            return apology(" NO enough MONEY!",400)
        uptd_cash= user_cash-transaction_value
        db.execute("UPDATE users SET cash = ? WHERE id=?",uptd_cash,user_id)
        date = datetime.datetime.now()
         # Insert username into database
        db.execute("INSERT INTO transactions (user_id,symbol,shares,price,date) VALUES (?,?,?,?,?)",
                        user_id,stock["symbol"],shares,stock["price"],date)
        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?;", session["user_id"])
    return render_template("history.html", transactions=transactions)


@app.route("/add_cash",methods=["GET", "POST"])
@login_required
def add_cash():
    """deposition """
    if request.method=="GET":
        return render_template("add.html")
    else:
        new_cash=int(request.form.get("new_cash"))
        if not new_cash :
            return apology("Give Some Amount")
        user_id=session["user_id"]
        user_cash_db=db.execute("SELECT cash FROM users WHERE id=:id",id=user_id)
        user_cash=user_cash_db[0]["cash"]

        uptd_cash= user_cash + new_cash
        db.execute("UPDATE users SET cash = ? WHERE id=?",uptd_cash,user_id)
        flash("Deposition Succesfull")
        return redirect("/")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        if not request.form.get("username"):
            return apology("MISSING USERNAME")

        if not request.form.get("password"):
            return apology("MISSING PASSWORD")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?;", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

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
def quote():
    """Get stock quote."""
    if request.method == "POST":
        # Ensure Symbol is exists
        symbol=request.form.get("symbol")

        quote = lookup(symbol)

        if not quote:
            return apology("invalid symbol", 400)
        if not symbol:
            return apology("MUST GIVE SYMBOL")
        stock=lookup(symbol.upper())
        if stock == None :
            return apology("symbol does not Exist")
        return render_template("quoted.html", price = stock["price"], symbol=stock["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not (username := request.form.get("username")):
            return apology("MISSING USERNAME")

        if not (password := request.form.get("password")):
            return apology("MISSING PASSWORD")

        if not (confirmation := request.form.get("confirmation")):
            return apology("PASSWORD DON'T MATCH")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?;", username)

        # Ensure username not in database
        if len(rows) != 0:
            return apology(f"The username '{username}' already exists. Please choose another name.")

        # Ensure first password and second password are matched
        if password != confirmation:
            return apology("password not matched")

        # Insert username into database
        id = db.execute("INSERT INTO users (username, hash) VALUES (?, ?);",
                        username, generate_password_hash(password))

        # Remember which user has logged in
        session["user_id"] = id   

        flash("Registered!")

        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol or shares <= 0:
            return apology("Invalid symbol or shares")

        user_id = session["user_id"]

        # Fetch current stock price
        quote = lookup(symbol)
        if not quote:
            return apology("Invalid stock symbol")

        price = quote["price"]

        # Fetch user's current shares for the symbol
        rows = db.execute("SELECT SUM(shares) as total_shares FROM transactions WHERE user_id = ? AND symbol = ?", user_id, symbol)
        if len(rows) != 1 or rows[0]["total_shares"] is None or rows[0]["total_shares"] < shares:
            return apology("Not enough shares")

        total_shares = rows[0]["total_shares"]

        # Calculate sale value
        sale_value = shares * price

        # Update transactions (record sale)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", user_id, symbol, -shares, price)

        # Update user's cash
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", sale_value, user_id)

        flash("Sold!")
        return redirect("/")

    else:
        user_id = session["user_id"]
        symbols = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) > 0", user_id)
        return render_template("sell.html", symbols=symbols)


@app.route("/reset", methods=["GET", "POST"])
@login_required
def reset():
    if request.method == "POST":
        if not (password := request.form.get("password")):
            return apology("MISSING OLD PASSWORD")

        rows = db.execute("SELECT * FROM users WHERE id = ?;", session["user_id"])

        if not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("INVALID PASSWORD")

        if not (new_password := request.form.get("new_password")):
            return apology("MISSING NEW PASSWORD")

        if not (confirmation := request.form.get("confirmation")):
            return apology("MISSING CONFIRMATION")

        if new_password != confirmation:
            return apology("PASSWORD NOT MATCH")

        db.execute("UPDATE users set hash = ? WHERE id = ?;",
                   generate_password_hash(new_password), session["user_id"])

        flash("Password reset successful!")

        return redirect("/")
    else:
        return render_template("reset.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
