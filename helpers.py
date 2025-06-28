import csv
import datetime
import pytz
import requests
import urllib
import uuid
import os

from flask import redirect, render_template, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def lookup(symbol):
    """Look up quote for symbol using Finnhub API."""
    API_KEY = os.environ.get('FINNHUB_API_KEY', 'demo')  # Use environment variable
    symbol = symbol.upper()
    url = f"https://finnhub.io/api/v1/quote?symbol={symbol}&token={API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if "c" in data and data["c"]:
            price = float(data["c"])
            return {"price": price, "symbol": symbol, "name": symbol}
        else:
            print(f"DEBUG: Invalid response for symbol {symbol}: {data}")
            return None
    except Exception as e:
        print(f"DEBUG: Exception occurred: {e}")
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"
