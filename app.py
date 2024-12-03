from flask import Flask, session, render_template, redirect, url_for, make_response, request, jsonify, send_from_directory
from flask_session import Session
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import x
import uuid
import time
import redis
import os
import random

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis', etc.
Session(app)


# app.secret_key = "your_secret_key"

##############################
##############################
##############################

def _________GET_________(): pass

##############################
##############################

##############################
@app.get("/images/<image_id>")
def view_image(image_id):
    return send_from_directory("./images", image_id)



##############################
@app.get("/test-set-redis")
def view_test_set_redis():
    redis_host = "redis"
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    # TODO: Get most populatar restaurants from mysql
    # restaurants [{},{},{}]
    # To interact with REDIS from vscode: docker exec -it fulldemo_redis_exam redis-cli
    # To interact with REDIS from vscode: docker exec -it CONTAINER_NAME_HERE redis-cli
    """

    for restaursnt in restaurants:
        HSET restaurant:restaurant["user_pk"] name restaurant["user_name"] cuisine "Italian" location "New York"
    """
    redis_client.set()
    redis_client.set("name", "Santiago", ex=10)
    # name = redis_client.get("name")
    return "name saved"

@app.get("/test-get-redis")
def view_test_get_redis():
    redis_host = "redis"
    redis_port = 6379
    redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
    name = redis_client.get("name")
    if not name: name = "no name"
    return name

##############################
@app.get("/")
def view_index():
    name = "X"
    return render_template("view_index.html", name=name)

##############################
@app.get("/login")
@x.no_cache
def view_login():
    ic(session)
    user = session.get("user")
    if user and isinstance(user, dict):
        roles = user.get("roles", [])
        if "admin" in roles:
            return redirect(url_for("view_admin"))
        if "customer" in roles:
            return redirect(url_for("view_customer"))
        if "partner" in roles:
            return redirect(url_for("view_partner"))
        if "restaurant" in roles:
            return redirect(url_for("view_restaurant"))
    return render_template("view_login.html", x=x, title="Login", message=request.args.get("message", ""))


##############################
@app.get("/customer")
@x.no_cache
def view_customer():
    if not session.get("user", ""):
        return redirect(url_for("view_login"))
    user = session.get("user")
    db, cursor = x.db()

    cursor.execute("""
        SELECT 
            users.*, -- All user columns
            MIN(items.item_image_1) AS item_image -- Select a single item image (e.g., the smallest lexicographically)
        FROM users
        JOIN users_roles ON users.user_pk = users_roles.user_role_user_fk
        JOIN roles ON users_roles.user_role_role_fk = roles.role_pk
        LEFT JOIN items ON users.user_pk = items.item_user_fk
        WHERE roles.role_name = 'restaurant'
        GROUP BY users.user_pk -- Group by user to avoid duplicates
        """)
    restaurants = cursor.fetchall()
    ic("Restaurant data with items", restaurants)


###### Used chatGPT to generate code for the leaflet-map ########
    # Function to generate random latitude and longitude within Copenhagen's bounds
    def generate_random_coordinates():
        # Latitude range for Copenhagen (approx. 55.61 to 55.73)
        lat = random.uniform(55.61, 55.73)
        # Longitude range for Copenhagen (approx. 12.48 to 12.65)
        lon = random.uniform(12.48, 12.65)
        # Return the generated latitude and longitude as a tuple
        return lat, lon

    # Iterate through the list of restaurants and generate random coordinates for all
    for restaurant in restaurants:
        lat, lon = generate_random_coordinates()  # Generate random coordinates for every restaurant
        restaurant['latitude'] = lat  # Assign latitude
        restaurant['longitude'] = lon  # Assign longitude
        # ic("Restaurant latitude:", lat)  # Debugging output
        # ic("Restaurant longitude:", lon)  # Debugging output
####### Code for the leaflet-map END ######

    return render_template("view_customer.html", user=user, restaurants=restaurants)

##############################
@app.get("/restaurant/<uuid:restaurant_id>")
def view_restaurant_items(restaurant_id):
    if not session.get("user", ""):
        return redirect(url_for("view_login"))
    user = session.get("user")
    db, cursor = x.db()

    # Fetch the specific restaurant by its UUID
    cursor.execute("""
        SELECT * FROM users 
        WHERE user_pk = %s 
        AND user_pk IN (
            SELECT user_role_user_fk 
            FROM users_roles
            WHERE user_role_role_fk = (
                SELECT role_pk FROM roles WHERE role_name = 'restaurant'
            )
        )
    """, (str(restaurant_id),))  # Pass UUID as string in tuple

    print("Restaurant ID:", str(restaurant_id))

    restaurant = cursor.fetchone()

    # Handle case where restaurant does not exist
    if not restaurant:
        return "Restaurant not found", 404

    # Fetch items for this specific restaurant
    cursor.execute("""
        SELECT item_title
        FROM items 
        WHERE item_user_fk = %s
    """, (str(restaurant_id),))  # Pass UUID as string in tuple

    items = cursor.fetchall()

    return render_template("view_restaurants_items.html", user=user, restaurant=restaurant, items=items)





##############################
@app.get("/partner")
@x.no_cache
def view_partner():
    if not session.get("user", ""):
        return redirect(url_for("view_login"))
    user = session.get("user")
    return render_template("view_partner.html", user=user)


##############################
@app.get("/admin")
@x.no_cache
def view_admin():
    if not session.get("user", ""):
        return redirect(url_for("view_login"))
    user = session.get("user")
    if not "admin" in user.get("roles", ""):
        return redirect(url_for("view_login"))
    
    db, cursor = x.db()
    cursor.execute("""  SELECT * FROM users
                        JOIN users_roles ON user_pk = user_role_user_fk  
                        JOIN roles ON user_role_role_fk = role_pk                
                        ORDER BY user_created_at DESC
                   """) #Get all users and their role
    users = cursor.fetchall()
    ic("Dette er user", users)

    cursor.execute("SELECT * FROM items ORDER BY item_created_at DESC") #Get all items
    items = cursor.fetchall()
    return render_template("view_admin.html", user=user, users=users, items=items, x=x)

    # TODO: husk at close db again.

##############################
@app.get("/restaurant")
@x.no_cache
def view_restaurant():
    if not session.get("user", ""):
        return redirect(url_for("view_login"))

    user = session.get("user")
    user_pk = session.get("user", {}).get("user_pk")
    print("User PK:", user_pk)

    if not user_pk:
        return redirect(url_for("view_login"))  # Redirect if user_pk is missing

    db, cursor = x.db()  # Assuming this returns a connection and cursor
    try:
        cursor.execute("""
        SELECT 
            item_pk,
            item_title,
            item_price,
            item_created_at,
            item_updated_at,
            item_image_1,
            item_image_2,
            item_image_3
        FROM items 
        WHERE item_user_fk = %s AND item_deleted_at = 0 
        ORDER BY item_created_at DESC
        """, (user_pk,))
        items = cursor.fetchall()
        
        for item in items:
            item["item_image_1_url"] = f"/images/{item['item_image_1']}" if item["item_image_1"] else None
            item["item_image_2_url"] = f"/images/{item['item_image_2']}" if item["item_image_2"] else None
            item["item_image_3_url"] = f"/images/{item['item_image_3']}" if item["item_image_3"] else None

        
    finally:
        db.close()  # Ensure the database connection is closed

    return render_template("view_restaurant.html", user=user, x=x, items=items)

    
##############################
@app.get("/profile")
@x.no_cache
def view_edit_profile():
    if not session.get("user", ""): 
        return redirect(url_for("view_login"))
    user = session.get("user")

    return render_template("view_edit_profile.html", x=x, title="Profile", user=user)
##############################
@app.get("/customer-signup")
@x.no_cache
def view_signup_customer():
    return render_template("view_signup_customer.html", x=x, title="Signup")

##############################
@app.get("/restaurant-signup")
@x.no_cache
def view_signup_restaurant():
    return render_template("view_signup_restaurant.html", x=x, title="Signup")

##############################
@app.get("/partner-signup")
@x.no_cache
def view_signup_partner():
    return render_template("view_signup_partner.html", x=x, title="Signup")

##############################
@app.get("/reset-password")
def view_forgot_password():
    return render_template("view_reset_password.html", title="Reset Password", x=x)

##############################
@app.get("/reset-password/<user_reset_password_key>")
def view_reset_password(user_reset_password_key):
    try:
        user_reset_password_key = x.validate_uuid4(user_reset_password_key)
        db, cursor = x.db()

        cursor.execute("""  SELECT user_pk
                        FROM users
                        WHERE user_reset_password_key = %s""", (user_reset_password_key,))
        user = cursor.fetchone()

        #When user_reset_password_key = 0 then if not user is true, and the customer is taken to an error-page
        if not user:
            raise x.CustomException("This link has already been used.", 400)

        # Render the reset password form
        return render_template("view_set_new_password.html", user_reset_password_key=user_reset_password_key, x=x)

    except Exception as ex:
        ic("I'm in the exception")  # Debugging
        if isinstance(ex, x.CustomException):
            ic(f"Exception message: {ex.message}, Code: {ex.code}") ## Debugging
            return render_template("view_400_error_to_customer.html", message=ex.message), ex.code
        return """<template mix-target="#toast" mix-bottom>System error occurred.</template>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
##############################
##############################

def _________POST_________(): pass

##############################
##############################
##############################

@app.post("/logout")
def logout():
    # ic("#"*30)
    # ic(session)
    session.pop("user", None)
    # session.clear()
    # session.modified = True
    # ic("*"*30)
    # ic(session)
    return redirect(url_for("view_login"))

##############################
@app.post("/signup_customer")
@x.no_cache
def signup_customer():
    try:
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()
        hashed_password = generate_password_hash(user_password)

        role_pk = "c56a4180-65aa-42ec-a945-5fd21dec0538"

        user_pk = str(uuid.uuid4())
        user_avatar = ""
        user_created_at = int(time.time())
        user_deleted_at = 0
        user_blocked_at = 0
        user_updated_at = 0
        user_verified_at = 0
        user_verification_key = str(uuid.uuid4())
        user_reset_password_key = 0

        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_pk, user_name, user_last_name, user_email, hashed_password,
             user_avatar, user_created_at, user_deleted_at, user_blocked_at, user_updated_at, user_verified_at, user_verification_key, user_reset_password_key),
        )

        cursor.execute(
            """
            INSERT INTO users_roles (user_role_user_fk, user_role_role_fk)
            VALUES (%s, %s)
            """,
            (user_pk, role_pk),
        )

        x.send_verify_email(user_email, user_verification_key)
        db.commit()

        # Redirect to login with a message
        message = "Account created, please verify your account."
        return f""""<template mix-redirect="/login?message={message}"></template>"""

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex):
                toast = render_template("___toast.html", message="email not available")
                return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
            return f"""<template mix-target="#toast" mix-bottom>System upgrading</template>""", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.post("/signup_partner")
@x.no_cache
def signup_partner():
    try:
        user_name = x.validate_user_name()
        user_last_name = x.validate_user_last_name()
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()
        hashed_password = generate_password_hash(user_password)

        role_pk = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

        user_pk = str(uuid.uuid4())
        user_avatar = ""
        user_created_at = int(time.time())
        user_deleted_at = 0
        user_blocked_at = 0
        user_updated_at = 0
        user_verified_at = 0
        user_verification_key = str(uuid.uuid4())
        user_reset_password_key = 0

        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_pk, user_name, user_last_name, user_email, hashed_password,
             user_avatar, user_created_at, user_deleted_at, user_blocked_at, user_updated_at, user_verified_at, user_verification_key, user_reset_password_key),
        )

        cursor.execute(
            """
            INSERT INTO users_roles (user_role_user_fk, user_role_role_fk)
            VALUES (%s, %s)
            """,
            (user_pk, role_pk),
        )

        x.send_verify_email(user_email, user_verification_key)
        db.commit()

        return """<template mix-redirect="/login"></template>""", 201

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex):
                toast = render_template("___toast.html", message="email not available")
                return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
            return f"""<template mix-target="#toast" mix-bottom>System upgrating</template>""", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
@app.post("/signup_restaurant")
@x.no_cache
def signup_restaurant():
    try:
        user_name = x.validate_user_name()
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()
        hashed_password = generate_password_hash(user_password)

        role_pk = "9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15"

        user_pk = str(uuid.uuid4())
        user_avatar = ""
        user_created_at = int(time.time())
        user_deleted_at = 0
        user_blocked_at = 0
        user_updated_at = 0
        user_verified_at = 0
        user_last_name = ""
        user_verification_key = str(uuid.uuid4())
        user_reset_password_key = 0

        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO users VALUES(%s, %s, "", %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_pk, user_name, user_email, hashed_password,
             user_avatar, user_created_at, user_deleted_at, user_blocked_at, user_updated_at, user_verified_at, user_verification_key, user_reset_password_key),
        )

        cursor.execute(
            """
            INSERT INTO users_roles (user_role_user_fk, user_role_role_fk)
            VALUES (%s, %s)
            """,
            (user_pk, role_pk),
        )

        x.send_verify_email(user_email, user_verification_key)
        db.commit()

        return """<template mix-redirect="/login"></template>""", 201

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            if "users.user_email" in str(ex):
                toast = render_template("___toast.html", message="email not available")
                return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
            return f"""<template mix-target="#toast" mix-bottom>System upgrating</template>""", 500
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################

# @app.post("/users")
# @x.no_cache
# def signup():
#     try:
#         user_name = x.validate_user_name()
#         user_last_name = x.validate_user_last_name()
#         user_email = x.validate_user_email()
#         user_password = x.validate_user_password()
#         hashed_password = generate_password_hash(user_password)
#         user_role = request.form.get("user_role")

#         # Get roles, which may come in as multiple entries for the same key
#         role_mapping = {
#             "customer": "c56a4180-65aa-42ec-a945-5fd21dec0538",
#             "restaurant": "9f8c8d22-5a67-4b6c-89d7-58f8b8cb4e15",
#             "partner": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
#         }

#         if user_role not in role_mapping:
#             raise x.CustomException("You must select a role", 400)
        
#         role_pk = role_mapping[user_role]
#         user_pk = str(uuid.uuid4())
#         user_avatar = ""
#         user_created_at = int(time.time())
#         user_deleted_at = 0
#         user_blocked_at = 0
#         user_updated_at = 0
#         user_verified_at = 0
#         user_verification_key = str(uuid.uuid4())

#         db, cursor = x.db()
#         q = 'INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
#         cursor.execute(q, (user_pk, user_name, user_last_name, user_email,
#                            hashed_password, user_avatar, user_created_at, user_deleted_at, user_blocked_at,
#                            user_updated_at, user_verified_at, user_verification_key))

        
#         # Insert into users_roles in db (junction table)
#         q_users_roles = """
#             INSERT INTO users_roles (user_role_user_fk, user_role_role_fk)
#             VALUES (%s, %s)
#             """
#         cursor.execute(q_users_roles, (user_pk, role_pk))

#         # The user needs to verify before they are able to login
#         x.send_verify_email(user_email, user_verification_key)
#         db.commit()

#         return """<template mix-redirect="/login"></template>""", 201

#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException):
#             toast = render_template("___toast.html", message=ex.message)
#             return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             if "users.user_email" in str(ex):
#                 toast = render_template("___toast.html", message="email not available")
#                 return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", 400
#             return f"""<template mix-target="#toast" mix-bottom>System upgrating</template>""", 500
#         return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()


##############################
@app.post("/login")
def login():
    try:
        # Validate user inputs
        user_email = x.validate_user_email()
        user_password = x.validate_user_password()

        # Query the database for the user
        db, cursor = x.db()
        q = """SELECT * FROM users WHERE user_email = %s"""
        cursor.execute(q, (user_email,))
        user_row = cursor.fetchone()

        if not user_row:
            toast = render_template("___toast.html", message="User not registered")
            return f"""<template mix-target="#toast">{toast}</template>""", 400

        if user_row["user_deleted_at"] != 0:
            toast = render_template("___toast.html", message="Account has been deleted")
            return f"""<template mix-target="#toast">{toast}</template>""", 403

        if user_row["user_verified_at"] == 0:
            toast = render_template("___toast.html", message="User not verified")
            return f"""<template mix-target="#toast">{toast}</template>""", 403

        if not check_password_hash(user_row["user_password"], user_password):
            toast = render_template("___toast.html", message="Invalid credentials")
            return f"""<template mix-target="#toast">{toast}</template>""", 401

        # Fetch role for the user
        role_query = """SELECT * FROM users_roles 
                        JOIN roles ON role_pk = user_role_role_fk
                        WHERE user_role_user_fk = %s"""
        cursor.execute(role_query, (user_row["user_pk"],))
        role_rows = cursor.fetchall()

        roles = [row["role_name"] for row in role_rows]

        # Prepare user session data
        user = {
            "user_pk": user_row["user_pk"],
            "user_name": user_row["user_name"],
            "user_last_name": user_row["user_last_name"],
            "user_email": user_row["user_email"],
            "roles": roles
        }
        ic(user)
        session["user"] = user

        # Redirect based on roles
        if len(roles) == 1:
            return f"""<template mix-redirect="/{roles[0]}"></template>"""
        return f"""<template mix-redirect="/"></template>"""
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrading</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.post("/items")
def create_item():
    try:
        # DONE_TODO: validate item_title, item_price
        item_user_fk = session.get("user").get("user_pk")
        item_pk = str(uuid.uuid4())
        item_title = x.validate_item_title()
        item_price = x.validate_item_price()
        
        item_created_at = int(time.time())
        item_deleted_at = 0
        item_blocked_at = 0
        item_updated_at = 0

        # Validate and save multiple images from a single input
        files = request.files.getlist("item_images")  # Retrieve multiple files
        if len(files) != 3:
            raise x.CustomException("Exactly 3 images are required", 400)
        
        image_filenames = []
        for file in files:
            file, filename = x.validate_individual_file(file)  # Validate each file
            file.save(os.path.join(x.UPLOAD_ITEM_FOLDER, filename))  # Save each image
            image_filenames.append(filename)

        # TODO: if saving the image went wrong, then rollback by going to the exception
        # TODO: Success, commit

        db, cursor = x.db()
        q = 'INSERT INTO items VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        cursor.execute(q, (item_pk, item_user_fk,  item_title, item_price,  image_filenames[0], image_filenames[1], image_filenames[2], item_created_at, item_deleted_at, item_blocked_at, item_updated_at))

        db.commit()

        return f"""<template mix-redirect="/restaurant"></template>"""
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrating</template>", 500
        return "<template>System under maintenance</template>", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
##############################
@app.post("/restaurant/<uuid:restaurant_id>/add_to_basket")
@x.no_cache
def add_to_basket(restaurant_id):
    try:
        if "basket" not in session:
            session["basket"] = []

        item_title = request.form.get("item_title")
        if not item_title:
            raise x.CustomException("Item title is required", 400)

        session["basket"].append(item_title)
        session.modified = True

        updated_basket = render_template("___basket.html", basket=session["basket"])
        return f"""<template mix-target="#basket" mix-replace>{updated_basket}</template>"""

    except Exception as ex:
        ic(ex)
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500


##############################
@app.post("/buy_all")
@x.no_cache
def buy_all():
    try:
        if "basket" not in session or not session["basket"]:
            raise x.CustomException("Basket is empty", 400)

        items = session["basket"]

        x.send_order_email(items)

        session["basket"] = []
        session.modified = True
        toast = render_template("___toast_ok.html", message="Order placed successfully!")
        return f"""<template mix-target="#basket" mix-replace><ul id="basket"></ul></template>
                    <template mix-target="#toast" mix-bottom>{toast}</template>"""

    except Exception as ex:
        ic(ex)  # Debug log
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        return f"""<template mix-target="#toast" mix-bottom>System under maintenance</template>""", 500

##############################
##############################
##############################

def _________PUT_________(): pass

##############################
##############################
##############################

@app.put("/items/<item_pk>")
def item_update(item_pk):
    try:
        # Validate inputs
        item_pk = x.validate_uuid4(item_pk)
        item_title = x.validate_item_title()
        item_price = x.validate_item_price()
        item_updated_at = int(time.time())

        # Dynamic query for images
        dynamic_images = []
        dynamic_images_values = []
        upload_folder = x.UPLOAD_ITEM_FOLDER

        if request.files.get("item_image_1"):
            file = request.files.get("item_image_1")
            unique_filename = f"{item_pk}_1.png"  # Create a unique filename using item_pk
            dynamic_images.append("item_image_1 = %s")
            dynamic_images_values.append(unique_filename)
            file.save(os.path.join(upload_folder, unique_filename))  # Save the file

        if request.files.get("item_image_2"):
            file = request.files.get("item_image_2")
            unique_filename = f"{item_pk}_2.png"  # Create a unique filename using item_pk
            dynamic_images.append("item_image_2 = %s")
            dynamic_images_values.append(unique_filename)
            file.save(os.path.join(upload_folder, unique_filename))  # Save the file

        if request.files.get("item_image_3"):
            file = request.files.get("item_image_3")
            unique_filename = f"{item_pk}_3.png"  # Create a unique filename using item_pk
            dynamic_images.append("item_image_3 = %s")
            dynamic_images_values.append(unique_filename)
            file.save(os.path.join(upload_folder, unique_filename))  # Save the file

        # Prepare query
        set_clause = ", ".join(dynamic_images)  # Dynamic part for images
        q = f"""
            UPDATE items
            SET item_title = %s, item_price = %s, item_updated_at = %s
            {', ' + set_clause if set_clause else ''}
            WHERE item_pk = %s
        """
        # Combine all parameter values
        values = [item_title, item_price, item_updated_at] + dynamic_images_values + [item_pk]

        # Debugging logs (optional)
        ic(q)
        ic(values)

        # Execute query
        db, cursor = x.db()
        cursor.execute(q, values)
        if cursor.rowcount != 1:
            x.raise_custom_exception("Cannot update item", 401)
        db.commit()

        # Return success response
        toast = render_template("___toast_ok.html", message="Item updated")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

    except Exception as ex:
        ic("Error during item update:")
        ic(ex)
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            if "users.user_email" in str(ex):
                return "<template>email not available</template>", 400
            return "<template>System upgrading</template>", 500
        return "<template>System under maintenance</template>", 500
    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()





############################################
@app.put("/users")
def user_update():
    try:
        if not session.get("user"): x.raise_custom_exception("please login", 401)

        user_pk = session.get("user").get("user_pk")
        roles = session.get("user").get("roles")
        user_name = x.validate_user_name()
        user_email = x.validate_user_email()

        if "restaurant" in roles:
            user_last_name = ""
        else:
            user_last_name = x.validate_user_last_name()

        user_updated_at = int(time.time())

        db, cursor = x.db()
        q = """ UPDATE users
                SET user_name = %s, user_last_name = %s, user_email = %s, user_updated_at = %s
                WHERE user_pk = %s
            """
        cursor.execute(q, (user_name, user_last_name, user_email, user_updated_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot update user", 401)
        db.commit()
        user = {
            "user_pk":user_pk,
            "user_name": user_name,
            "user_last_name": user_last_name,
            "user_email": user_email,
            "roles": roles
        }  

        session["user"] = user  
        return f"""<template mix-redirect="/profile"></template>"""
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            if "users.user_email" in str(ex): return "<template>email not available</template>", 400
            return "<template>System upgrating</template>", 500
        return "<template>System under maintenance</template>", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################

##############################
@app.put("/delete")
def delete_user():
    try:
        user_pk = session.get("user", {}).get("user_pk")
        if not user_pk:
            raise x.CustomException("User not logged in", 403)

        db, cursor = x.db()
        q = "SELECT user_password FROM users WHERE user_pk = %s"
        cursor.execute(q, (user_pk,))
        user = cursor.fetchone()

        if not user:
            raise x.CustomException("User not found", 404)

        # Get hashed password
        hashed_password = user["user_password"]
        ic(hashed_password)

        confirm_password = request.form.get("confirm_password")
        # Ensure input isn't empty
        if not confirm_password:
            raise x.CustomException("Password is required to delete the account", 400)
        ic(confirm_password)

        # Verify the plain password against the hash
        if not check_password_hash(hashed_password, confirm_password):
            raise x.CustomException("Password is not correct", 400)

        # Proceed with deletion
        user_deleted_at = int(time.time())
        db, cursor = x.db()
        q = """
            UPDATE users 
            SET user_deleted_at = %s 
            WHERE user_pk = %s
        """
        cursor.execute(q, (user_deleted_at, user_pk))
        db.commit()

        # Send confirmation email
        x.send_confirm_delete()
        # Clear session storage
        session.clear()

        toast = render_template("___toast_ok.html", message="E-mail sent")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""
        #return redirect(url_for("view_index", message="E-mail sent"))
        #return f"""<template mix-redirect="/"></template>"""

    except Exception as ex:
        print(f"Error: {ex}")  # Debugging
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast">{toast}</template>""", ex.code
        return """<template mix-target="#toast">System error occurred.</template>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()
        
##############################

# @app.put("/delete_item")
# def delete_item():
#     try:
#         user_pk = session.get("user", {}).get("user_pk")
#         if not user_pk:
#             raise x.CustomException("User not logged in", 403)
        
#         item_pk = request.form.get("item_pk", "").strip()
#         if not item_pk:
#             raise x.CustomException("Item ID is required", 400)
#         db, cursor = x.db()
#         q = "SELECT * FROM items WHERE item_pk = %s AND item_user_fk = %s AND item_deleted_at = 0"
#         cursor.execute(q, (item_pk, user_pk))
#         item = cursor.fetchone()
        
        
        
#         return q
#     except Exception as ex:
#         pass
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()
    
@app.put("/delete_item")
def delete_item():
    try:
        # Get the user session
        item_user_fk = session.get("user", {}).get("user_pk").strip()
        if not item_user_fk:
            raise x.CustomException("User not logged in", 403)

        # Get item_pk from the form
        item_pk = request.form.get("item_pk", "").strip()
        if not item_pk:
            raise x.CustomException("Item ID is required", 400)

        # Validate ownership or existence of the item
        db, cursor = x.db()
        q = "SELECT * FROM items WHERE item_pk = %s AND item_user_fk = %s AND item_deleted_at = 0"
        cursor.execute(q, (item_pk, item_user_fk))
        item = cursor.fetchone()
        if not item:
            raise x.CustomException("Item not found or unauthorized", 404)

        # Soft delete the item
        item_deleted_at = int(time.time())
        q = """
            UPDATE items 
            SET item_deleted_at = %s 
            WHERE item_pk = %s AND item_user_fk = %s
        """
        cursor.execute(q, (item_deleted_at, item_pk, item_user_fk))
        db.commit()

        # Return success response
        return f"""<template mix-redirect="/restaurant"</template>"""
        # toast = render_template("___toast_ok.html", message="Item deleted successfully.")
        # return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

    except Exception as ex:
        print(f"Error: {ex}")  # Debugging the exact error
        if "db" in locals():
            db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast">{toast}</template>""", ex.code
        return """<template mix-target="#toast">System error occurred.</template>""", 500

    finally:
        if "cursor" in locals():
            cursor.close()
        if "db" in locals():
            db.close()
            





##############################
@app.put("/users/block/<user_pk>")
def user_block(user_pk):
    try:
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        user_pk = x.validate_uuid4(user_pk)
        user_blocked_at = int(time.time())
        db, cursor = x.db()
        q = 'UPDATE users SET user_blocked_at = %s, user_updated_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_blocked_at, user_blocked_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot block user", 400)
        db.commit()
        
        # send the blocked user email and include the user_pk to the x function
        x.send_blocked_email(user_pk = user_pk)

        user = {"user_pk":user_pk}
        btn_unblock = render_template("___btn_unblock_user.html", user=user)
        toast = render_template("___toast.html", message="User blocked")
        return f"""
                <template 
                mix-target='#block-{user_pk}' 
                mix-replace>
                    {btn_unblock}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/users/unblock/<user_pk>")
def user_unblock(user_pk):
    try:
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        user_pk = x.validate_uuid4(user_pk)
        user_unblocked_at = 0
        user_updated_at = int(time.time())

        db, cursor = x.db()
        q = 'UPDATE users SET user_blocked_at = %s, user_updated_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_unblocked_at, user_updated_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot unblock user", 400)
        db.commit()
        
        # send the unblocked user email and include the user_pk to the x function
        x.send_unblocked_email(user_pk = user_pk)
        user = {"user_pk":user_pk}
        btn_block = render_template("___btn_block_user.html", user=user)
        toast = render_template("___toast_ok.html", message="User unblocked")
        return f"""
                <template 
                mix-target='#unblock-{user_pk}' 
                mix-replace>
                    {btn_block}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """
    except Exception as ex:

        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/items/block/<item_pk>")
def item_block(item_pk):
    try:
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        item_pk = x.validate_uuid4(item_pk)
        item_blocked_at = int(time.time())
        db, cursor = x.db()
        q = 'UPDATE items SET item_blocked_at = %s, item_updated_at = %s WHERE item_pk = %s'
        cursor.execute(q, (item_blocked_at, item_blocked_at, item_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot block item", 400)
        db.commit()
        
        # send the blocked item email and include the item_pk to the x function
        x.send_blocked_email(item_pk = item_pk)

        item = {"item_pk":item_pk}
        btn_unblock = render_template("___btn_unblock_item.html", item=item)
        toast = render_template("___toast.html", message="Item blocked")
        return f"""
                <template 
                mix-target='#block-{item_pk}' 
                mix-replace>
                    {btn_unblock}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """


    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/items/unblock/<item_pk>")
def item_unblock(item_pk):
    try:
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        item_pk = x.validate_uuid4(item_pk)
        item_unblocked_at = 0
        item_updated_at = int(time.time())

        db, cursor = x.db()
        q = 'UPDATE items SET item_blocked_at = %s, item_updated_at = %s WHERE item_pk = %s'
        cursor.execute(q, (item_unblocked_at, item_updated_at, item_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot unblock item", 400)
        db.commit()
        
        # send the unblocked item email and include the item_pk to the x function
        x.send_unblocked_email(item_pk = item_pk)

        item = {"item_pk":item_pk}
        btn_block = render_template("___btn_block_item.html", item=item)
        toast = render_template("___toast_ok.html", message="Item unblocked")
        return f"""
                <template 
                mix-target='#unblock-{item_pk}' 
                mix-replace>
                    {btn_block}
                </template>
                <template mix-target="#toast" mix-bottom>
                    {toast}
                </template>
                """
    except Exception as ex:

        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>Database error</template>", 500
        return "<template>System under maintenance</template>", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()



##############################
@app.put("/forgot-password")
def forgot_password():
    try:
        user_email = x.validate_user_email()
        db, cursor = x.db()
        user_reset_password_key = str(uuid.uuid4())
        
        q = """ UPDATE users
                SET user_reset_password_key = %s
                WHERE user_email = %s
                """

        cursor.execute(q, (user_reset_password_key, user_email))
        if cursor.rowcount != 1: x.raise_custom_exception("user not found", 400)
        db.commit()

        # Send the reset email
        x.send_reset_email(user_email, user_reset_password_key)

        toast = render_template("___toast_ok.html", message="Reset email sent.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""
        
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrating</template>", 500        
        return "<template>System under maintenance</template>", 500 

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/reset-password/<user_reset_password_key>")
def new_password(user_reset_password_key):
    try:
        user_reset_password_key = x.validate_uuid4(user_reset_password_key)
        user_password = x.validate_user_password()
        user_repeat_password = request.form.get("user_repeat_password", "")
        if user_password != user_repeat_password: x.raise_custom_exception("password do not match", 400)
        
        user_updated_at = int(time.time())
        hashed_password = generate_password_hash(user_password)

        db, cursor = x.db()
        q = ("""    UPDATE users
                    SET user_password = %s, user_updated_at = %s
                    WHERE user_reset_password_key = %s""")
        cursor.execute(q, (hashed_password, user_updated_at, user_reset_password_key))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot save password", 400) 

        # The user_reset_password_key is sat to 0, so the user can't keep on updating the password
        cursor.execute("""
         UPDATE users
         SET user_reset_password_key = 0
         WHERE user_reset_password_key = %s
        """, (user_reset_password_key,))

        db.commit()
        
        message = "Password has been updated, please login"
        return f""""<template mix-redirect="/login?message={message}"></template>"""

    
    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): 
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code    
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "<template>System upgrating</template>", 500        
        return "<template>System under maintenance</template>", 500  
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
##############################
##############################

def _________DELETE_________(): pass

##############################
##############################
##############################


# @app.delete("/users/<user_pk>")
# def user_delete(user_pk):
#     try:
#         # Check if user is logged
#         if not session.get("user", ""): return redirect(url_for("view_login"))
#         # Check if it is an admin
#         if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
#         user_pk = x.validate_uuid4(user_pk)
#         user_deleted_at = int(time.time())
#         db, cursor = x.db()
#         q = 'UPDATE users SET user_deleted_at = %s WHERE user_pk = %s'
#         cursor.execute(q, (user_deleted_at, user_pk))
#         if cursor.rowcount != 1: x.raise_custom_exception("cannot delete user", 400)
#         db.commit()
#         return """<template>user deleted</template>"""

#     except Exception as ex:

#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException):
#             return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "<template>Database error</template>", 500
#         return "<template>System under maintenance</template>", 500

#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()




##############################
##############################
##############################

def _________BRIDGE_________(): pass

##############################
##############################
##############################


##############################
@app.get("/verify/<verification_key>")
@x.no_cache
def verify_user(verification_key):
    try:
        ic(verification_key)
        verification_key = x.validate_uuid4(verification_key)
        user_verified_at = int(time.time())

        db, cursor = x.db()
        q = """ UPDATE users
                SET user_verified_at = %s
                WHERE user_verification_key = %s"""
        cursor.execute(q, (user_verified_at, verification_key))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot verify account", 400)
        db.commit()
        return redirect(url_for("view_login", message="User verified, please login"))

    except Exception as ex:
        ic(ex)
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException): return ex.message, ex.code
        if isinstance(ex, x.mysql.connector.Error):
            ic(ex)
            return "Database under maintenance", 500
        return "System under maintenance", 500
    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


