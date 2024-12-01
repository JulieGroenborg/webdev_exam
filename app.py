from flask import Flask, session, render_template, redirect, url_for, make_response, request, jsonify, send_from_directory
from flask_session import Session
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
import x
import uuid
import time
import redis
import os

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
    return render_template("view_customer.html", user=user)

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
    cursor.execute("SELECT * FROM users ORDER BY user_created_at DESC") #Get all users
    users = cursor.fetchall()

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

    db, cursor = x.db()
    cursor.execute("SELECT * FROM items ORDER BY item_created_at DESC")
    items = cursor.fetchall()

    return render_template("view_restaurant.html", user=user, x=x, items=items)

     # TODO: husk at close db again.
    

##############################

@app.get("/reset_password")
def reset_request():
    return render_template("view_reset_password.html", title="Reset Password", x=x)

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

        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_pk, user_name, user_last_name, user_email, hashed_password,
             user_avatar, user_created_at, user_deleted_at, user_blocked_at, user_updated_at, user_verified_at, user_verification_key),
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

        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO users VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_pk, user_name, user_last_name, user_email, hashed_password,
             user_avatar, user_created_at, user_deleted_at, user_blocked_at, user_updated_at, user_verified_at, user_verification_key),
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
        user_verification_key = str(uuid.uuid4())

        db, cursor = x.db()
        cursor.execute(
            """
            INSERT INTO users VALUES(%s, %s, "", %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (user_pk, user_name, user_email, hashed_password,
             user_avatar, user_created_at, user_deleted_at, user_blocked_at, user_updated_at, user_verified_at, user_verification_key),
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

        # Fetch roles for the user
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
@app.post("/forgot-password")
def forgot_password():
    try:
        user_email = request.form.get("user_email")
        if not user_email:
            raise x.CustomException("Email is required", 400)

        # Fetch user by email
        db, cursor = x.db()
        q = "SELECT user_pk FROM users WHERE user_email = %s AND user_deleted_at = 0"
        cursor.execute(q, (user_email,))
        user = cursor.fetchone()

        if not user:
            raise x.CustomException("Email not found", 404)

        # Generate a reset token
        reset_token = str(uuid.uuid4())

        # Store the reset token in the database
        q = "UPDATE users SET user_verification_key = %s WHERE user_pk = %s"
        cursor.execute(q, (reset_token, user["user_pk"]))
        db.commit()

        # Send the reset email (pass only the reset token)
        x.send_reset_email(user_email, reset_token)


        toast = render_template("___toast_ok.html", message="Reset email sent.")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""

    except Exception as ex:
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        return """<template mix-target="#toast" mix-bottom>System error occurred.</template>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.post("/reset_password")
def update_password():
    try:
        user_pk = request.form.get("user_pk")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if not user_pk or not new_password or not confirm_password:
            raise x.CustomException("All fields are required", 400)

        if new_password != confirm_password:
            raise x.CustomException("Passwords do not match", 400)

        # Hash the new password
        hashed_password = generate_password_hash(new_password)

        # Get the current epoch timestamp
        updated_at = int(time.time())

        # Update the user's password and updated_at in the database
        db, cursor = x.db()
        q = """
            UPDATE users 
            SET user_password = %s, user_updated_at = %s 
            WHERE user_pk = %s
        """
        cursor.execute(q, (hashed_password, updated_at, user_pk))
        db.commit()

        print(f"Password updated successfully for user_pk: {user_pk}")  # Debugging
        return redirect(url_for("view_login", message="Password updated, please login"))

    except Exception as ex:
        print(f"Error: {ex}")  # Debugging
        if "db" in locals(): db.rollback()
        if isinstance(ex, x.CustomException):
            toast = render_template("___toast.html", message=ex.message)
            return f"""<template mix-target="#toast" mix-bottom>{toast}</template>""", ex.code
        return """<template mix-target="#toast" mix-bottom>System error occurred.</template>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()


##############################
@app.put("/delete-user")
def delete_user():
    try:
        if not session.get("user"): x.raise_custom_exception("please login", 401)

        user_pk = session.get("user").get("user_pk")
        user_deleted_at = int(time.time())

        db, cursor = x.db()
        q = """
            UPDATE users 
            SET user_deleted_at = %s 
            WHERE user_pk = %s
        """
        cursor.execute(q, (user_deleted_at, user_pk))
        db.commit()

        print(f"User soft-deleted successfully for user_pk: {user_pk}") 

        session.clear()

        print(f"User succesfully deleted for user_pk: {user_pk}") 
        toast = render_template("___toast_ok.html", message="user deleted")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""
        return redirect(url_for("view_login", message="User succesfully deleted"))

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
##############################
##############################

def _________PUT_________(): pass

##############################
##############################
##############################

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

@app.put("/items/<item_pk>")
def item_update(item_pk):
    try:
        item_pk = x.validate_uuid4(item_pk)
        item_title = x.validate_item_title()
        item_price = x.validate_item_price()

        item_updated_at = int(time.time())

        # TODO: add validation for the image later
        # Dynamic query
        dynamic_images = []
        dynamic_images_name = []
        if request.files.get("item_image_1") : 
            dynamic_images.append("item_image_1 = %s")
            dynamic_images_name.append("1.png")

        if request.files.get("item_image_2") : 
            dynamic_images.append("item_image_2 = %s")
            dynamic_images_name.append("2.png")
        
        if request.files.get("item_image_3") : 
            dynamic_images.append("item_image_3 = %s")
            dynamic_images_name.append("3.png")

        db, cursor = x.db()
        q = f""" UPDATE items SET item_title = %s, item_price = %s, item_updated_at = %s, {', '.join(dynamic_images)}  WHERE item_pk = %s"""
        ic(q)
        dynamic_images_name_str = ','.join(dynamic_images_name)
        cursor.execute(q, (item_title, item_price, item_updated_at, dynamic_images_name_str, item_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot update item", 401)
        db.commit()

        toast = render_template("___toast_ok.html", message="Item updated")
        return f"""<template mix-target="#toast" mix-bottom>{toast}</template>"""
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
@app.put("/users/block/<user_pk>")
def user_block(user_pk):
    try:
        if not "admin" in session.get("user").get("roles"): return redirect(url_for("view_login"))
        user_pk = x.validate_uuid4(user_pk)
        user_blocked_at = int(time.time())

        db, cursor = x.db()
        q = 'UPDATE users SET user_blocked_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_blocked_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot block user", 400)
        db.commit()
        # btn_unblock = render_template("___btn_unblock_user.html", user=user)
        # toast = render_template("__toast.html", message="User blocked")
        # return f"""
        #         <template 
        #         mix-target='#block-{user_pk}' 
        #         mix-replace>
        #             {btn_unblock}
        #         </template>
        #         <template mix-target="#toast" mix-bottom>
        #             {toast}
        #         </template>
        #         """

        # Kan det virkelig være rigtigt kan jeg skal redirect? Kan jeg ikke bare udskifte knappen?
        return f"""
                <template mix-redirect="/admin"></template>
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
        user_blocked_at = 0
        db, cursor = x.db()
        q = 'UPDATE users SET user_blocked_at = %s WHERE user_pk = %s'
        cursor.execute(q, (user_blocked_at, user_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot unblock user", 400)
        db.commit()
        # toast = render_template("___toast_ok.html", message="User unblocked")
        # return f"""<template mix-target="#toast" mix-bottom>
        #             {toast}
        #         </template>"""
        return f"""
                <template mix-redirect="/admin"></template>
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
        q = 'UPDATE items SET item_blocked_at = %s WHERE item_pk = %s'
        cursor.execute(q, (item_blocked_at, item_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot block item", 400)
        db.commit()
        # btn_unblock = render_template("___btn_unblock_user.html", user=user)
        # toast = render_template("__toast.html", message="User blocked")
        # return f"""
        #         <template 
        #         mix-target='#block-{user_pk}' 
        #         mix-replace>
        #             {btn_unblock}
        #         </template>
        #         <template mix-target="#toast" mix-bottom>
        #             {toast}
        #         </template>
        #         """

        # Kan det virkelig være rigtigt kan jeg skal redirect? Kan jeg ikke bare udskifte knappen?
        return f"""
                <template mix-redirect="/admin"></template>
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
        item_blocked_at = 0
        db, cursor = x.db()
        q = 'UPDATE items SET item_blocked_at = %s WHERE item_pk = %s'
        cursor.execute(q, (item_blocked_at, item_pk))
        if cursor.rowcount != 1: x.raise_custom_exception("cannot unblock item", 400)
        db.commit()
        # toast = render_template("___toast_ok.html", message="User unblocked")
        # return f"""<template mix-target="#toast" mix-bottom>
        #             {toast}
        #         </template>"""
        return f"""
                <template mix-redirect="/admin"></template>
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


##############################

@app.get("/reset_password/<token>")
def reset_password(token):
    try:
        print(f"Token received: {token}")  # Debugging
        # Verify the reset token
        db, cursor = x.db()
        q = "SELECT user_pk FROM users WHERE user_verification_key = %s AND user_deleted_at = 0"
        cursor.execute(q, (token,))
        user = cursor.fetchone()

        print(f"User fetched: {user}")  # Debugging

        if not user:
            raise x.CustomException("Invalid or expired reset link", 400)

        # Render the reset password form
        return render_template("view_set_new_password.html", user_pk=user["user_pk"])

    except Exception as ex:
        print(f"Error: {ex}")  # Debugging
        if isinstance(ex, x.CustomException):
            return f"""<template mix-target="#toast" mix-bottom>{ex.message}</template>""", ex.code
        return """<template mix-target="#toast" mix-bottom>System error occurred.</template>""", 500

    finally:
        if "cursor" in locals(): cursor.close()
        if "db" in locals(): db.close()

##############################
# @app.get("/confirm_delete/<delete_key>")
# @x.no_cache
# def confirm_delete_user(delete_key):
#     try:
#         ic(delete_key)
#         delete_key = x.validate_uuid4(delete_key)
#         user_verified_at = int(time.time())

#         db, cursor = x.db()
#         q = """ UPDATE users
#                 SET user_verified_at = %s
#                 WHERE user_verification_key = %s"""
#         cursor.execute(q, (user_verified_at, delete_key))
#         if cursor.rowcount != 1: x.raise_custom_exception("cannot verify account", 400)
#         db.commit()
#         return redirect(url_for("view_login", message="User verified, please login"))

#     except Exception as ex:
#         ic(ex)
#         if "db" in locals(): db.rollback()
#         if isinstance(ex, x.CustomException): return ex.message, ex.code
#         if isinstance(ex, x.mysql.connector.Error):
#             ic(ex)
#             return "Database under maintenance", 500
#         return "System under maintenance", 500
#     finally:
#         if "cursor" in locals(): cursor.close()
#         if "db" in locals(): db.close()
