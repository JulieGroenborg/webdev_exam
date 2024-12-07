from flask import request, make_response
from functools import wraps
import mysql.connector
import re
import os
import uuid

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)

UNSPLASH_ACCESS_KEY = 'YOUR_KEY_HERE'
ADMIN_ROLE_PK = "16fd2706-8baf-433b-82eb-8c7fada847da"
CUSTOMER_ROLE_PK = "c56a4180-65aa-42ec-a945-5fd21dec0538"
PARTNER_ROLE_PK = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
RESTAURANT_ROLE_PK = "9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15"

###############################
class CustomException(Exception):
    def __init__(self, message, code):
        super().__init__(message)  # Initialize the base class with the message
        self.message = message  # Store additional information (e.g., error code)
        self.code = code  # Store additional information (e.g., error code)

def raise_custom_exception(error, status_code):
    raise CustomException(error, status_code)

##############################
def db():
    db = mysql.connector.connect(
        host="mysql",      # Replace with your MySQL server's address or docker service name "mysql"
        user="root",  # Replace with your MySQL username
        password="password",  # Replace with your MySQL password
        database="company"   # Replace with your MySQL database name
    )
    cursor = db.cursor(dictionary=True)
    return db, cursor

##############################
def no_cache(view):
    @wraps(view)
    def no_cache_view(*args, **kwargs):
        response = make_response(view(*args, **kwargs))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    return no_cache_view

##############################
def allow_origin(origin="*"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Call the wrapped function
            response = make_response(f(*args, **kwargs))
            # Add Access-Control-Allow-Origin header to the response
            response.headers["Access-Control-Allow-Origin"] = origin
            # Optionally allow other methods and headers for full CORS support
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS, PUT, DELETE"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
            return response
        return decorated_function
    return decorator

##############################
USER_NAME_MIN = 2
USER_NAME_MAX = 20
USER_NAME_REGEX = f"^.{{{USER_NAME_MIN},{USER_NAME_MAX}}}$"
def validate_user_name():
    error = f"name {USER_NAME_MIN} to {USER_NAME_MAX} characters"
    user_name = request.form.get("user_name", "").strip()
    if not re.match(USER_NAME_REGEX, user_name): raise_custom_exception(error, 400)
    return user_name

##############################
USER_LAST_NAME_MIN = 2
USER_LAST_NAME_MAX = 20
USER_LAST_NAME_REGEX = f"^.{{{USER_LAST_NAME_MIN},{USER_LAST_NAME_MAX}}}$"
def validate_user_last_name():
    error = f"last name {USER_LAST_NAME_MIN} to {USER_LAST_NAME_MAX} characters"
    user_last_name = request.form.get("user_last_name", "").strip() # None
    if not re.match(USER_LAST_NAME_REGEX, user_last_name): raise_custom_exception(error, 400)
    return user_last_name

##############################
REGEX_EMAIL = "^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"
def validate_user_email():
    error = "email invalid"
    user_email = request.form.get("user_email", "").strip()
    if not re.match(REGEX_EMAIL, user_email): raise_custom_exception(error, 400)
    return user_email

##############################
USER_PASSWORD_MIN = 8
USER_PASSWORD_MAX = 50
REGEX_USER_PASSWORD = f"^.{{{USER_PASSWORD_MIN},{USER_PASSWORD_MAX}}}$"
def validate_user_password():
    error = f"password {USER_PASSWORD_MIN} to {USER_PASSWORD_MAX} characters"
    user_password = request.form.get("user_password", "").strip()
    if not re.match(REGEX_USER_PASSWORD, user_password): raise_custom_exception(error, 400)
    return user_password

##############################
REGEX_UUID4 = "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
def validate_uuid4(uuid4 = ""):
    error = f"invalid uuid4"
    if not uuid4:
        uuid4 = request.values.get("uuid4", "").strip()
    if not re.match(REGEX_UUID4, uuid4): raise_custom_exception(error, 400)
    return uuid4

##############################
UPLOAD_ITEM_FOLDER = './images'
ALLOWED_ITEM_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "JPG"}
def validate_individual_file(file):
    if file.filename == "":
        raise_custom_exception("Image name is invalid", 400)
    if file:
        file_extension = os.path.splitext(file.filename)[1][1:]
        if file_extension not in ALLOWED_ITEM_IMAGE_EXTENSIONS:
            raise_custom_exception("Invalid image extension", 400)
        filename = str(uuid.uuid4()) + "." + file_extension
        return file, filename
    
##############################
def send_verify_email(to_email, user_verification_key):
    try:
        # Create a gmail fullflaskdemomail
        # Enable (turn on) 2 step verification/factor in the google account manager
        # Visit: https://myaccount.google.com/apppasswords
        # My key/password: atxxbyhicjzrsnhs  

        # Email and password of the sender's Gmail account
        sender_email = "fullflaskdemoemailexam@gmail.com"
        password = "atxxbyhicjzrsnhs"  # If 2FA is on, use an App Password instead

        # Receiver email address
        receiver_email = "fullflaskdemoemailexam@gmail.com"
        
        # Create the email message
        message = MIMEMultipart()
        message["From"] = "My company name"
        message["To"] = receiver_email
        message["Subject"] = "Please verify your account"

        # Body of the email
        body = f"""To verify your account, please <a href="http://127.0.0.1/verify/{user_verification_key}">click here</a>"""
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")

        return "email sent"
       
    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass


##############################
ITEM_TITLE_MIN = 2
ITEM_TITLE_MAX = 50
ITEM_TITLE_REGEX = f"^.{{{ITEM_TITLE_MIN},{ITEM_TITLE_MAX}}}$"
def validate_item_title():
    error = f"name {ITEM_TITLE_MIN} to {ITEM_TITLE_MAX} characters"
    item_title = request.form.get("item_title", "").strip()
    if not re.match(ITEM_TITLE_REGEX, item_title): raise_custom_exception(error, 400)
    return item_title

##############################
# Constants for price validation
MIN_PRICE = 1
MAX_PRICE = 999.99
PRICE_MAX_DECIMALS = 2
PRICE_REGEX = r"^\d{1,3}(\.\d{1,2})?$"
def validate_item_price():
    error = f"Price must be a number between {MIN_PRICE} and {MAX_PRICE} with up to {PRICE_MAX_DECIMALS} decimal."
    price = request.form.get("item_price", "").strip()

    # Check if price is provided and matches the regex
    if not price or not re.match(PRICE_REGEX, price):
        raise_custom_exception(error, 400)
    
    return float(price)  # Return the price as a float for further processing

##############################
def send_reset_email(user_email, user_reset_password_key):
    try:
        # Sender email and app password
        sender_email = "fullflaskdemoemailexam@gmail.com"
        password = "atxxbyhicjzrsnhs"  # App Password for Gmail (with 2FA enabled)

        # Construct the reset URL
        reset_url = f"http://127.0.0.1/reset-password/{user_reset_password_key}"

        # Create the email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = sender_email # Change to user_email before deployment
        message["Subject"] = "Reset Your Password"

        # Format the email body similarly to verify_email
        body = f"""
        <p>To reset your password, please click the link below:</p>
        <p><a href="{reset_url}">Reset Your Password</a></p>
        <p>If you did not request this, please ignore this email.</p>
        """
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, sender_email, message.as_string())
        print("Reset password email sent successfully!")

        return "email sent"

    except Exception as ex:
        raise CustomException("Cannot send email", 500)

##############################
def send_blocked_email(user_pk=None, item_pk=None):
    try:
        # Create a gmail fullflaskdemomail
        # Enable (turn on) 2 step verification/factor in the google account manager
        # Visit: https://myaccount.google.com/apppasswords
        # My key/password: atxxbyhicjzrsnhs  

        # Email and password of the sender's Gmail account
        sender_email = "fullflaskdemoemailexam@gmail.com"
        password = "atxxbyhicjzrsnhs"  # If 2FA is on, use an App Password instead

        # Receiver email address
        receiver_email = "fullflaskdemoemailexam@gmail.com"
        
        # Create the email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        
        if user_pk:
            message["Subject"] = "User blocked from Viento"
            body = f"""<p> User with ID {user_pk} has been blocked from Viento.</p>  
                       <p> Please contact an admin if you think this is a mistake or you require further information. </p>"""
        elif item_pk:
            message["Subject"] = "Item blocked from Viento"
            body = f"""<p> User with ID {item_pk} has been blocked from Viento.</p>  
                       <p> Please contact an admin if you think this is a mistake or you require further information. </p>"""
        else:
            raise ValueError("Either user_pk or item_pk must be provided.")

        # body = f"""You have been blocked from viento."""
        # Body of the email
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")

        return "email sent"
       
    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass

##############################
def send_unblocked_email(user_pk=None, item_pk=None):
    try:
        # Create a gmail fullflaskdemomail
        # Enable (turn on) 2 step verification/factor in the google account manager
        # Visit: https://myaccount.google.com/apppasswords
        # My key/password: atxxbyhicjzrsnhs  

        # Email and password of the sender's Gmail account
        sender_email = "fullflaskdemoemailexam@gmail.com"
        password = "atxxbyhicjzrsnhs"  # If 2FA is on, use an App Password instead

        # Receiver email address
        receiver_email = "fullflaskdemoemailexam@gmail.com"
        
        # Create the email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        
        # Checks whether it's an item or user that's being unblocked.
        # if the route sends a user_pk it will send the user body, and the same for item_pk if it's sent.
        if user_pk:
            message["Subject"] = "User unblocked from Viento"
            body = f"""<p> User with ID {user_pk} has been unblocked from Viento.  </p> """
        elif item_pk:
            message["Subject"] = "Item unblocked from Viento"
            body = f"""<p> Item with ID {item_pk} has been unblocked from Viento.  </p> """
        else:
            raise ValueError("Either user_pk or item_pk must be provided.")

        # Body of the email
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")

        return "email sent"
       
    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass

##############################
def send_confirm_delete():
    try:
        # Create a gmail fullflaskdemomail
        # Enable (turn on) 2 step verification/factor in the google account manager
        # Visit: https://myaccount.google.com/apppasswords
        # My key/password: atxxbyhicjzrsnhs  

        # Email and password of the sender's Gmail account
        sender_email = "fullflaskdemoemailexam@gmail.com"
        password = "atxxbyhicjzrsnhs"  # If 2FA is on, use an App Password instead

        # Receiver email address
        receiver_email = "fullflaskdemoemailexam@gmail.com"
        
        # Create the email message
        message = MIMEMultipart()
        message["From"] = "My company name"
        message["To"] = receiver_email
        message["Subject"] = "Confirm deletion of account"

        # Body of the email
        body = f"""Your profile from Viento is now deleted, if you want to create a new profile <a href="http://127.0.0.1">click here</a>"""
        #body = f"""To confirm your deletion of your account, please <a href="http://127.0.0.1/verify/{user_pk}">click here</a>"""
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully!")

        return "email sent"

    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass

##############################
def send_order_email(items):
    try:
        # Email and password of the sender's Gmail account
        sender_email = "fullflaskdemoemailexam@gmail.com"
        password = "atxxbyhicjzrsnhs"  # If 2FA is on, use an App Password instead

        # Receiver email address
        receiver_email = "fullflaskdemoemailexam@gmail.com"

        # Create the email message
        message = MIMEMultipart()
        message["From"] = sender_email
        message["To"] = receiver_email
        message["Subject"] = "Order Confirmation - Viento"

        # Create the email body with the order details
        body = f"""
        <p>Your order has been recieved and your food is on the way!</p>
        <ul>
        """
        for item in items:
            body += f"<li>{item}</li>"
        body += "</ul>"

        # Attach the body to the email
        message.attach(MIMEText(body, "html"))

        # Connect to Gmail's SMTP server and send the email
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()  # Upgrade the connection to secure
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message.as_string())
        print("Order email sent successfully!")

        return "Email sent successfully!"

    except Exception as ex:
        raise_custom_exception("cannot send email", 500)
    finally:
        pass
