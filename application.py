import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from flask import url_for

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
    # SYMBOL | NAME | SHARES | CURRENT PRICE | TOTAL VALUE ( shares * price)

    user_id=session["user_id"]

    # List of stocks
    rows = db.execute("SELECT symbol, SUM(shares), price, name, total FROM portfolio WHERE user_id=:user_id GROUP BY symbol", user_id=user_id)

    # Get cash balance
    cash_rows = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
    cash_balance = cash_rows[0]["cash"]

    # Total value of all shares + cash holdings
    total_value = cash_balance

    # Get total value of shares for each stock
    for row in rows:
        # Add row "value" to dict rows and set it to the value of shares * price, format price in usd
        row["value"] = usd(row["SUM(shares)"] * row["price"])
        row["price"] = usd(row["price"])

    return render_template("index.html", rows=rows, cash_balance=usd(cash_balance), total_value=usd(total_value))

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    else:
        # Lookup stock price
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        # Return error if stock is not found
        if not quote:
            return apology("Stock not found")

        else:
            try:
                # Render an apology if the input is not a positive integer.
                shares = int(request.form.get("shares"))

                if shares < 1:
                    return apology("Please enter a positive integer")

            except ValueError:
                return apology("Please enter an integer")

            # SELECT how much cash the user currently has in users
            row = db.execute("SELECT cash FROM USERS WHERE id = :id", id=session["user_id"])
            cash = float(row[0]["cash"])

            shareprice = quote['price']
            totalprice = shares * shareprice

            # Render an apology, without completing a purchase, if the user cannot afford the number of shares at the current price.
            if totalprice > cash:
                return apology("You can't afford that many shares")

            # Store transaction records in database. Username, Stock, Shares, Price. Date and time is recorded automatically in database
            db.execute("INSERT INTO portfolio (user_id, symbol, name, shares, price, total) VALUES (:user_id, :symbol, :name, :shares, :price, :total)",
                    user_id = session['user_id'],
                    symbol = quote['symbol'],
                    name = quote['name'],
                    shares=shares,
                    price=shareprice,
                    total=totalprice)

            new_balance = cash - totalprice

            # Update cash holdings
            db.execute("UPDATE users SET cash = :new_balance WHERE id = :id ", new_balance=new_balance, id=session['user_id'])

            flash("Bought " + str(shares) + " shares of " + quote['name'] + "!")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user_id=session["user_id"]

    transactions = db.execute("SELECT * FROM portfolio WHERE user_id=:user_id", user_id=user_id)

    # Format in $usd
    for row in transactions:
        row["total"] = usd(row["price"] * row["shares"])

    return render_template("history.html", transactions=transactions)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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

    # Require that a user input a stock’s symbol, implemented as a text field whose name is symbol.
    if request.method == "GET":
        return render_template("quote.html")

    #Submit the user’s input via POST to /quote.
    else:
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        # Return error if stock is not found
        if not quote:
            return apology("Stock not found")
        return render_template("quoted.html", quote=quote)

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Display register.html if user is not registered
    if request.method == "GET":
        return render_template("register.html")

    # Get input from form and add to database
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        password2 = request.form.get("password2")

        if password != password2:
            return apology("Passwords don't match")

        # Look for username in database
        check = db.execute("SELECT * FROM users WHERE username =:username",username=username)

        # If username does not exist already, add new user to database
        if not check:
            hash_pwd = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            db.execute("INSERT INTO users (username, hash) VALUES(?,?)",username,hash_pwd)

            #Return to login page
            flash('You were successfully registered!')

            return render_template("login.html")

        else:
            return apology("Username already in use")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_id=session["user_id"]

    # List stocks in portfolio
    symbol = db.execute("SELECT symbol, SUM(shares) FROM portfolio WHERE user_id=:user_id GROUP BY symbol", user_id=user_id)

    if request.method == "GET":
        return render_template("sell.html", symbol=symbol)

    else:
        try:
            # Get input from form
            sell_symbol = request.form.get("symbol")
            sell_shares = int(request.form.get("shares"))


            # Error checking
            if sell_shares < 1:
                return apology("Please enter a positive integer")

        # Render an apology if the input is not an integer.
        except ValueError:
            return apology("Please enter an integer")

        # Return apology if no input is provided
        if not sell_symbol:
            return apology("Missing symbol")

        if not sell_shares:
            return apology("Missing shares")

        if sell_shares <= 0:
            return render_template("sell.html", symbol=symbol)


        # Return apology if user does not have that many stocks in portfolio
        shares_rows = db.execute("SELECT SUM(shares) FROM portfolio WHERE user_id=:user_id AND symbol =:symbol", user_id=user_id, symbol=sell_symbol)
        shares_owned = shares_rows[0]["SUM(shares)"]

        if sell_shares > shares_owned:
            return apology("Too many shares")

        else:
        # Record transaction
            # Lookup stock price
            quote = lookup(sell_symbol)
            shareprice = quote['price']

            totalprice = sell_shares * shareprice

            # Add sell transaction to database
            db.execute("INSERT INTO portfolio (user_id, symbol, name, shares, price, total) VALUES (:user_id, :sell_symbol, :name, :shares, :price, :total)",
                        user_id = session['user_id'],
                        sell_symbol = quote['symbol'],
                        name = quote['name'],
                        shares= -sell_shares,
                        price=shareprice,
                        total=totalprice)

            # SELECT how much cash the user currently has in users
            row = db.execute("SELECT cash FROM USERS WHERE id = :id", id=session["user_id"])
            cash = float(row[0]["cash"])

            # Update cash balance
            totalprice = sell_shares * shareprice
            new_balance = cash + totalprice

            # Update cash holdings in database
            db.execute("UPDATE users SET cash = :new_balance WHERE id = :id ", new_balance=new_balance, id=user_id)

            flash("Sold " + str(sell_shares) + " shares of " + quote['name'] + "!")
            return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    return render_template("settings.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "GET":
        return render_template("changepassword.html")

    else:
            # Get input from form
            oldpassword = request.form.get("oldpassword")
            newpassword = request.form.get("newpassword")
            newpassword2 = request.form.get("newpassword2")

            # Query database for old password
            rows = db.execute("SELECT id, hash FROM users WHERE id=:id", id=session["user_id"])
            old_password_hash = rows[0]["hash"]

            # Generate hash from the old password input by the user
            passwordhash = generate_password_hash(oldpassword, method='pbkdf2:sha256', salt_length=8)

            # Compare hashed password with hash in database
            check_hash = check_password_hash(old_password_hash,oldpassword)

            if check_hash == True:

                if newpassword != newpassword2:
                    return apology("Passwords don't match")

                #Hash new password
                new_password_hash = generate_password_hash(newpassword, method='pbkdf2:sha256', salt_length=8)

                # Update database
                db.execute("UPDATE users SET hash=:new_password_hash WHERE id =:id", new_password_hash=new_password_hash, id=session["user_id"])

                flash("Password changed!")

                return redirect("/")

            else:
                return apology("Wrong password!")


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():

    # Show how much cash the user currently has
    cash_rows = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
    cash_balance = cash_rows[0]["cash"]

    if request.method == "GET":
        return render_template("cash.html", cash_balance=usd(cash_balance))

    else:

        # Get input from form
        try:
            add_cash = int(request.form.get("addcash"))
            new_balance = cash_balance + add_cash

            # Update cash balance
            db.execute("UPDATE users SET cash=:new_balance WHERE id = :id", new_balance=new_balance, id=session["user_id"])

            # Flash message (" USD added to cash balance)
            flash("Added " + str(usd(add_cash)) + " to cash balance ")
            return redirect("/settings")

        except ValueError:
            return apology("Wrong input")





# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


