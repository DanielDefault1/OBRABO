import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_stocks = db.execute("SELECT symbol, quantity FROM user_stocks WHERE id = :user_id", user_id=session["user_id"])
    portfolio_data = []
    total_cash = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])[0]['cash']
    total_cash = round(total_cash, 2)
    total_cash_str = total_cash
    total_portfolio = total_cash
    total_portfolio_str = total_portfolio
    for stock in user_stocks:
        symbol = stock["symbol"]
        quantity = stock["quantity"]
        db.execute("SELECT stock_quantity, stock_price FROM transactions WHERE id = :user_id AND symbol = :symbol AND transaction_type = 'BUY'",
                   user_id=session["user_id"], symbol=symbol)
        stock_info = lookup(symbol)

        if stock_info is not None:
            current_price = round(stock_info["price"],2)
            total_price = round(current_price * quantity, 2)
            total_portfolio = round(total_cash + total_price, 2)

            current_price_str = "{:.2f}".format(current_price)
            total_price_str = "{:.2f}".format(total_price)
            total_cash_str = "{:.2f}".format(total_cash)
            total_portfolio_str = "{:.2f}".format(total_portfolio)

        portfolio_data.append({
            "symbol": symbol,
            "quantity": quantity,
            "total_price": total_price_str,
            "current_price": current_price_str
        })
    return render_template("index.html", portfolio_data=portfolio_data, total_cash=total_cash_str, total_portfolio=total_portfolio_str)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock_info = lookup(symbol)

        # Checks for symbol and shares filling
        if not symbol:
            return apology("Empty stock symbol")
        try:
            shares = int(shares)
            if shares <= 0:
                return apology("Shares must be a positive integer")
        except ValueError:
            return apology("Shares must be a positive integer")

        # Checks for lookup return on finding the symbol
        if stock_info is None:
            return apology("Stock symbol doesn't exist")

        # Gets stock price and user current cash
        stock_total_price = round(stock_info["price"], 2)
        rows = db.execute("SELECT cash FROM users WHERE id = :user_id", user_id=session["user_id"])
        user_cash = rows[0]["cash"]

        # Compare user's current cash with the stock price * the amount user wants to buy
        if stock_total_price * int(shares) > user_cash:
            return apology("You are not that rich to buy that amount of stocks. GO AWAY!!!")
        else:
            purchase_value = round(stock_total_price * int(shares), 2)
            new_cash = user_cash - purchase_value
            db.execute("UPDATE users SET cash = :new_cash WHERE id = :user_id", new_cash=new_cash, user_id=session["user_id"])

            # insert registers into transactions table
            transaction_type = "BUY"
            db.execute("INSERT INTO transactions (id, symbol, stock_quantity, stock_price, total_price, transaction_type, transaction_datetime) VALUES (:user_id, :symbol, :stock_quantity, :stock_price, :total_price, :transaction_type, datetime('now'))",
                       user_id=session["user_id"], symbol=symbol.upper(), stock_quantity=shares, stock_price=stock_total_price, total_price=purchase_value, transaction_type=transaction_type)

            # Update user current stock quantity possession
            rows = db.execute("SELECT quantity FROM user_stocks WHERE id = :id AND symbol = :symbol",
                              id=session["user_id"], symbol=symbol)
            if not rows:
                db.execute("INSERT INTO user_stocks (id, symbol, quantity) VALUES (:id, :symbol, :quantity)",
                           id=session["user_id"], symbol=symbol.upper(), quantity=int(shares))
            else:
                db.execute("UPDATE user_stocks SET quantity = quantity + :quantity WHERE id = :id AND symbol = :symbol",
                           id=session["user_id"], symbol=symbol.upper(), quantity=int(shares))

        flash("Your purchase was successful!")
        return index()

    if request.method == "GET":
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT symbol, stock_quantity, total_price, transaction_type, transaction_datetime FROM transactions WHERE id = :id", id=session["user_id"])
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
    # Check if the request comes via POST and assign the user input into a variable that will be used in the lookup function
    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock_info = lookup(symbol)
        if stock_info is None:
            return apology("Invalid stock symbol")
        if stock_info is not None:
            stock_info["price"] = "{:.2f}".format(stock_info["price"])
        return render_template("quoted.html", stock_info=stock_info)

    # Check if the request method is GET and then redirect the user back to the quote.html page
    if request.method == "GET":
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Checks for user's inputs on username and password twice
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # If any of fields are blank, return error message
        if not username or not password or not confirmation:
            return apology("Please provide both username and your password twice")

        # Checks for matching passwords on both fields
        if password != confirmation:
            return apology("VOCÊ É BURRO POR ACASO??? SEU ARROMBADO!!!")

        # Now checks for existing user name in db
        hashed_password = generate_password_hash(password)
        existing_user = db.execute("SELECT * FROM users WHERE username=:username", username=username)
        if existing_user:
            return apology("Username already exists. Please choose another one.")
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :hash)", username=username, hash=hashed_password)
        return render_template("login.html")

    # return the register template if anything goes wrong at the end of the loop OR if the request is not a POST type
    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    symbols = [stock['symbol'] for stock in db.execute("SELECT symbol FROM user_stocks WHERE id = :id", id=session["user_id"])]

    if request.method == "POST":
        symbol_to_sell = request.form.get("symbol").upper()
# Checks if the user has typed a positive number
        try:
            shares = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares must be a positive integer")

        # Checks if the user has the stock
        owned_stocks = db.execute("SELECT symbol FROM user_stocks WHERE id = :id", id=session["user_id"])
        owns_stock = False
        for stock in owned_stocks:
            if stock['symbol'].upper() == symbol_to_sell:
                owns_stock = True
                current_quantity = db.execute(
                    "SELECT quantity FROM user_stocks WHERE id = :id AND symbol = :symbol_to_sell", id=session["user_id"], symbol_to_sell=symbol_to_sell)
                if current_quantity[0]['quantity'] >= shares:
                    stock_info = lookup(symbol_to_sell)
                    stock_total_price = stock_info["price"]
                    purchase_value = stock_total_price * int(shares)
                    transaction_type = "SELL"
                    db.execute("INSERT INTO transactions (id, symbol, stock_quantity, stock_price, total_price, transaction_type, transaction_datetime) VALUES (:user_id, :symbol, :stock_quantity, :stock_price, :total_price, :transaction_type, datetime('now'))",
                               user_id=session["user_id"], symbol=symbol_to_sell.upper(), stock_quantity=shares, stock_price=stock_total_price, total_price=purchase_value, transaction_type=transaction_type)
                    flash("Stock sold!")
                    db.execute("UPDATE user_stocks SET quantity = quantity - :quantity WHERE id = :id AND symbol = :symbol_to_sell",
                               id=session["user_id"], symbol_to_sell=symbol_to_sell.upper(), quantity=int(shares))
                    db.execute("DELETE FROM user_stocks WHERE quantity = 0")
                    return index()
                else:
                    return apology("You do not own this amount of stocks!")
        if not owns_stock:
            return apology("You do not own this stock!")

    return render_template("sell.html", symbols=symbols)


@app.route("/cash", methods=["GET", "POST"])
@login_required
def cash():
    """Allows user to add more cash to the account"""
    if request.method == "POST":
        new_cash_input = request.form.get("new_cash")
        if new_cash_input is None:
            print(new_cash_input)
            return apology("The inserted value is not a number, don't try to fool us!!!")
        try:
            new_cash = round(float(new_cash_input), 2)
        except ValueError:
            return apology("The inserted value is not a number, don't try to fool us!!!")
        db.execute("UPDATE users SET cash = cash + :new_cash WHERE id = :id", new_cash=new_cash, id=session["user_id"])
        flash(f"${format(new_cash, '.2f')} added to your account successfully.", "success")

    return render_template("cash.html")
