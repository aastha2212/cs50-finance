# CS50 Finance - Stock Trading Simulation Platform

A comprehensive web application that simulates real stock trading using live market data. Built as part of Harvard's CS50 course, this project demonstrates full-stack web development skills with Python, Flask, and modern web technologies.

![CS50 Finance](https://img.shields.io/badge/CS50-Finance-blue)
![Python](https://img.shields.io/badge/Python-3.8+-green)
![Flask](https://img.shields.io/badge/Flask-2.0+-lightgrey)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-blue)

## 🚀 Features

### Core Functionality
- **User Authentication**: Secure registration and login with password hashing
- **Real-time Trading**: Buy and sell stocks with live market data
- **Portfolio Management**: Track holdings, cash balance, and total portfolio value
- **Interactive Charts**: Portfolio value over time and holdings breakdown
- **Personal Watchlist**: Monitor favorite stocks with real-time updates
- **Stock Quotes**: Get real-time stock information with intelligent autocomplete
- **Transaction History**: Complete record of all trading activities

### Technical Features
- **Responsive Design**: Works seamlessly on desktop and mobile devices
- **Security**: CSRF protection, input validation, and secure session handling
- **Performance**: Optimized API calls and efficient database queries
- **Error Handling**: Graceful handling of API failures and edge cases

## 🛠️ Tech Stack

### Backend
- **Python 3.8+**: Core programming language
- **Flask**: Web framework for building the application
- **SQLite**: Lightweight database for storing user data and transactions
- **CS50 Library**: Harvard's library for database operations

### Frontend
- **HTML5 & CSS3**: Structure and styling
- **JavaScript**: Interactive features and API calls
- **Bootstrap 5**: Responsive UI framework
- **Chart.js**: Data visualization for portfolio charts

### APIs & Services
- **Finnhub API**: Real-time stock market data
- **Flask-WTF**: CSRF protection and form handling
- **Werkzeug**: Password hashing and security utilities

## 📋 Prerequisites

Before running this application, make sure you have:

- Python 3.8 or higher installed
- A Finnhub API key (free tier available)
- Git for version control

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/cs50-finance.git
cd cs50-finance
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Set Up Environment Variables
Create a `.env` file in the root directory:
```bash
# API Keys
FINNHUB_API_KEY=your_finnhub_api_key_here

# Flask Configuration
SECRET_KEY=your_secret_key_here
FLASK_ENV=development
```

### 4. Initialize the Database
The application will automatically create the necessary database tables on first run.

### 5. Run the Application
```bash
flask run
```

The application will be available at `http://127.0.0.1:5000`

## 📖 Usage

### Getting Started
1. **Register**: Create a new account with a username and password
2. **Get Cash**: New users start with $10,000 in virtual cash
3. **Quote Stocks**: Search for stocks using company names or symbols
4. **Buy/Sell**: Execute trades with real-time market prices
5. **Monitor**: Track your portfolio performance with interactive charts
6. **Watchlist**: Add stocks to your personal watchlist for easy monitoring

### Features Walkthrough
- **Portfolio Dashboard**: View your current holdings, cash balance, and total portfolio value
- **Transaction History**: See all your past buy/sell activities
- **Real-time Data**: All stock prices and market data are updated in real-time
- **Responsive Design**: Use the application on any device - desktop, tablet, or mobile

## 🔒 Security Features

- **Password Hashing**: All passwords are hashed using Werkzeug's security functions
- **CSRF Protection**: All forms are protected against Cross-Site Request Forgery
- **Session Management**: Secure session handling with configurable timeouts
- **Input Validation**: All user inputs are validated and sanitized
- **SQL Injection Prevention**: Using parameterized queries throughout

## 🤝 Contributing

This is a CS50 course project, but if you find any bugs or have suggestions for improvements, feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is part of Harvard's CS50 course. The original CS50 Finance project is created by David J. Malan and the CS50 team.

## 🙏 Acknowledgments

- **Professor David J. Malan** and the CS50 team for creating this amazing course
- **Harvard University** for providing free access to quality computer science education
- **Finnhub** for providing the stock market data API
- **Bootstrap** and **Chart.js** teams for the excellent frontend libraries

## 📞 Support

If you encounter any issues or have questions:

1. Check the [CS50 Finance documentation](https://cs50.harvard.edu/x/2024/psets/9/finance/)
2. Review the [CS50 FAQ](https://cs50.harvard.edu/x/2024/faqs/)
3. Join the [CS50 Discord community](https://discord.gg/cs50)

---

**Built with ❤️ as part of Harvard's CS50 course** 

