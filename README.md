
# TrustVault - Secure Document Management System

TrustVault is a Flask-based web application for securely managing and sharing documents.

## Features

- User Registration and Login
- Secure Document Upload and Download
- Document Sharing
- Revoke Document Access
- Role-Based Access Control
- Activity Logging
- Document Search and Categories

## Technologies Used

- Python
- Flask
- Flask-SQLAlchemy
- Flask-Login
- SQLite
- HTML and CSS

## Installation

1. Install Python 3.11.
2. Open the project folder in the terminal.
3. Create a virtual environment:

   `python -m venv .venv`

4. Activate it on Windows:

   `.venv\Scripts\Activate.ps1`

5. Install the required packages:

   `python -m pip install -r requirements.txt`

6. Configure the required environment variables in `.env`.

## Run the Application

`python -m flask --app app:create_app run --debug`

Open http://127.0.0.1:5000 in your browser.

## Security

Do not upload `.env`, database files, private documents, or secret keys to GitHub.
