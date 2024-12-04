import x
import uuid
import time
import random
from werkzeug.security import generate_password_hash
from faker import Faker

fake = Faker()

from icecream import ic
ic.configureOutput(prefix=f'***** | ', includeContext=True)


db, cursor = x.db()


def insert_user(user):       
    q = f"""
        INSERT INTO users
        VALUES (%s, %s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s)        
        """
    values = tuple(user.values())
    cursor.execute(q, values)

def insert_item(item):       
    q = f"""
        INSERT INTO items
        VALUES (%s, %s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s ,%s)        
        """
    values = tuple(item.values())
    cursor.execute(q, values)




try:


    
    ##############################
    cursor.execute("DROP TABLE IF EXISTS items") # dependent table
    cursor.execute("DROP TABLE IF EXISTS users_roles") # dependent table
    cursor.execute("DROP TABLE IF EXISTS users")
  
    
    q = """
        CREATE TABLE users (
            user_pk CHAR(36),
            user_name VARCHAR(20) NOT NULL,
            user_last_name VARCHAR(20) NOT NULL,
            user_email VARCHAR(100) NOT NULL UNIQUE,
            user_password VARCHAR(255) NOT NULL,
            user_created_at INTEGER UNSIGNED,
            user_deleted_at INTEGER UNSIGNED,
            user_blocked_at INTEGER UNSIGNED,
            user_updated_at INTEGER UNSIGNED,
            user_verified_at INTEGER UNSIGNED,
            user_verification_key CHAR(36),
            user_reset_password_key CHAR(36),
            PRIMARY KEY(user_pk)
        )
        """        
    cursor.execute(q)


#     ##############################
    
    q = """
        CREATE TABLE items (
            item_pk CHAR(36),
            item_user_fk CHAR(36),
            item_title VARCHAR(50) NOT NULL,
            item_price DECIMAL(5,2) NOT NULL,
    
            item_image_1 VARCHAR(50),
            item_image_2 VARCHAR(50),
            item_image_3 VARCHAR(50),

            item_created_at INTEGER UNSIGNED,
            item_deleted_at INTEGER UNSIGNED,
            item_blocked_at INTEGER UNSIGNED,
            item_updated_at INTEGER UNSIGNED,
            PRIMARY KEY(item_pk)
        );
        """        
    cursor.execute(q)
    cursor.execute("ALTER TABLE items ADD FOREIGN KEY (item_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE ON UPDATE RESTRICT") 


    ##############################
    cursor.execute("DROP TABLE IF EXISTS roles")
    q = """
        CREATE TABLE roles (
            role_pk CHAR(36),
            role_name VARCHAR(10) NOT NULL UNIQUE,
            PRIMARY KEY(role_pk)
        );
        """        
    cursor.execute(q)


    ##############################    
    q = """
        CREATE TABLE users_roles (
            user_role_user_fk CHAR(36),
            user_role_role_fk CHAR(36),
            PRIMARY KEY(user_role_user_fk, user_role_role_fk)
        );
        """        
    cursor.execute(q)
    cursor.execute("ALTER TABLE users_roles ADD FOREIGN KEY (user_role_user_fk) REFERENCES users(user_pk) ON DELETE CASCADE ON UPDATE RESTRICT") 
    cursor.execute("ALTER TABLE users_roles ADD FOREIGN KEY (user_role_role_fk) REFERENCES roles(role_pk) ON DELETE CASCADE ON UPDATE RESTRICT") 





    ############################## 
    # Create roles
    q = f"""
        INSERT INTO roles (role_pk, role_name)
        VALUES ("{x.ADMIN_ROLE_PK}", "admin"), ("{x.CUSTOMER_ROLE_PK}", "customer"), 
        ("{x.PARTNER_ROLE_PK}", "partner"), ("{x.RESTAURANT_ROLE_PK}", "restaurant")
        """
    cursor.execute(q)

    ############################## 
    # Create admin user
    user_pk = "3b1f6532-abf1-4d4f-8d02-61f7890ebed9"
    user = {
        "user_pk" : user_pk,
        "user_name" : "Santiago",
        "user_last_name" : "Donoso",
        "user_email" : "admin@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "user_reset_password_key" : 0
    }            
    insert_user(user)
    # Assign role to admin user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.ADMIN_ROLE_PK}")        
        """    
    cursor.execute(q)    

    ############################## 
    # Create customer
    user_pk = "4218788d-03b7-4812-bd7d-31c8859e92d8"
    user = {
        "user_pk" : user_pk,
        "user_name" : "John",
        "user_last_name" : "Customer",
        "user_email" : "customer@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "user_reset_password_key" : 0
    }
    insert_user(user)
    # Assign role to customer user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.CUSTOMER_ROLE_PK}")        
        """    
    cursor.execute(q) 
    
    user_pk = "048d5f1c-a1e7-4dd7-a40a-250ad162489e"
    user = {
        "user_pk" : user_pk,
        "user_name" : "JohnGlemteKoden",
        "user_last_name" : "Customer",
        "user_email" : "customer2@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "user_reset_password_key" : "dc2ed7b7-8786-41c2-a3f7-249800add5e8"
    }
    insert_user(user)
    # Assign role to customer user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.CUSTOMER_ROLE_PK}")        
        """    
    cursor.execute(q) 
    
    # Create unverified customer
    user_pk = "1e8047ec-5c9d-4dc0-86d7-2dd8a4fe995d"
    user = {
        "user_pk" : user_pk,
        "user_name" : "UnverifiedJohn",
        "user_last_name" : "Customer",
        "user_email" : "Unverifiedcustomer@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : 0,
        "user_verification_key" : "2722bdea-432b-4f0b-b441-2a5e1dc27e66",
        "user_reset_password_key" : 0
    }
    insert_user(user)
#     # Assign role to customer user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.CUSTOMER_ROLE_PK}")        
        """    
    cursor.execute(q)


    ############################## 
    # Create partner
    user_pk = "b38fa0dd-16c2-4fbf-a7c9-8e5956578064"
    user = {
        "user_pk" : user_pk,
        "user_name" : "John",
        "user_last_name" : "Partner",
        "user_email" : "partner@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "user_reset_password_key" : 0
        
    }
    insert_user(user)
    # Assign role to partner user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.PARTNER_ROLE_PK}")        
        """    
    cursor.execute(q)

    ############################## 
    # Create restaurant
    user_pk = "27763272-712a-4d0a-b574-cad7318106a0"
    user = {
        "user_pk" : user_pk,
        "user_name" : "Johns Diner",
        "user_last_name" : "Restaurant",
        "user_email" : "restaurant@fulldemo.com",
        "user_password" : generate_password_hash("password"),
        "user_created_at" : int(time.time()),
        "user_deleted_at" : 0,
        "user_blocked_at" : 0,
        "user_updated_at" : 0,
        "user_verified_at" : int(time.time()),
        "user_verification_key" : str(uuid.uuid4()),
        "user_reset_password_key" : 0
    }
    insert_user(user)
    
    # Create item for restaurant 27763272-712a-4d0a-b574-cad7318106a0
    item_fk = "f27507c0-241e-45f8-aa07-0d47b496b037"
    item = {
        "item_pk"         : item_fk,
        "item_user_fk"    : user_pk,
        "item_title"      : "Spaghetti Carbonara",
        "item_price"      : 15.99,
        "item_image_1"    : "dish_1.jpg",
        "item_image_2"    : "dish_2.jpg",
        "item_image_3"    : "dish_3.jpg",
        "item_created_at" : int(time.time()),
        "item_deleted_at" : 0,
        "item_blocked_at" : 0,
        "item_updated_at" : 0
    }
    insert_item(item)
    
#     # Assign role to restaurant user
    q = f"""
        INSERT INTO users_roles (user_role_user_fk, user_role_role_fk) VALUES ("{user_pk}", 
        "{x.RESTAURANT_ROLE_PK}")        
        """    
    cursor.execute(q)


#     ############################## 
#     # Create 10 customer

    domains = ["example.com", "testsite.org", "mydomain.net", "website.co", "fakemail.io", "gmail.com", "hotmail.com"]
    user_password = hashed_password = generate_password_hash("password")
    for _ in range(10):
        user_pk = str(uuid.uuid4())
        user_verified_at = random.choice([0,int(time.time())])
        user = {
            "user_pk" : user_pk,
            "user_name" : fake.first_name(),
            "user_last_name" : fake.last_name(),
            "user_email" : fake.unique.user_name() + "@" + random.choice(domains),
            "user_password" : user_password,
            # user_password = hashed_password = generate_password_hash(fake.password(length=20))
            "user_created_at" : int(time.time()),
            "user_deleted_at" : 0,
            "user_blocked_at" : 0,
            "user_updated_at" : 0,
            "user_verified_at" : user_verified_at,
            "user_verification_key" : str(uuid.uuid4()),
            "user_reset_password_key" : 0
        }

        insert_user(user)
        cursor.execute("""INSERT INTO users_roles (
            user_role_user_fk,
            user_role_role_fk)
            VALUES (%s, %s)""", (user_pk, x.CUSTOMER_ROLE_PK))


#     ############################## 
#     # Create 10 partners

    user_password = hashed_password = generate_password_hash("password")
    for _ in range(10):
        user_pk = str(uuid.uuid4())
        user_verified_at = random.choice([0,int(time.time())])
        user = {
            "user_pk" : user_pk,
            "user_name" : fake.first_name(),
            "user_last_name" : fake.last_name(),
            "user_email" : fake.unique.email(),
            "user_password" : user_password,
            "user_created_at" : int(time.time()),
            "user_deleted_at" : 0,
            "user_blocked_at" : 0,
            "user_updated_at" : 0,
            "user_verified_at" : user_verified_at,
            "user_verification_key" : str(uuid.uuid4()),
            "user_reset_password_key" : 0
        }

        insert_user(user)

        cursor.execute("""
        INSERT INTO users_roles (
            user_role_user_fk,
            user_role_role_fk)
            VALUES (%s, %s)
        """, (user_pk, x.PARTNER_ROLE_PK))

    ############################## 
    # Create 10 restaurants
    # Dishes available
    dishes = ["Spaghetti Carbonara", "Chicken Alfredo", "Beef Wellington", "Sushi", "Pizza Margherita", "Tacos", 
              "Caesar Salad", "Fish and Chips", "Pad Thai", "Dim Sum", "Croissant", "Ramen", "Lasagna", "Burrito", 
              "Chicken Parmesan", "Tom Yum Soup", "Shawarma", "Paella", "Hamburger", "Pho", "Chicken Tikka Masala", 
              "Moussaka", "Goulash", "Bangers and Mash", "Peking Duck", "Falafel", "Ceviche", "Chili Con Carne", 
              "Ratatouille", "Beef Stroganoff", "Fajitas", "Samosas", "Lobster Roll", "Arancini", "Tiramisu", 
              "Beef Empanadas", "Poutine", "Biryani", "Hummus", "Schnitzel", "Meatloaf", "Quiche", "Paella Valenciana", 
              "Clam Chowder", "Sweet and Sour Pork", "Enchiladas", "Crepes", "Masala Dosa", "Gnocchi", "Jambalaya", 
              "Pork Ribs", "Tandoori Chicken", "Nasi Goreng", "Kimchi", "Roti", "Lamb Tagine", "Risotto", 
              "Croque Monsieur", "Beef Burritos", "Baked Ziti", "Yakitori", "Fettuccine Alfredo", "Peking Duck Pancakes", 
              "Empanadas", "Ahi Poke", "Cacciatore", "Pappardelle", "Cannelloni", "Empanadas de Pollo", "Gado-Gado", 
              "Carne Asada", "Chicken Katsu", "Falafel Wrap", "Maki Rolls", "Stuffed Bell Peppers", "Souvlaki", 
              "Bibimbap", "Tofu Stir Fry", "Chilaquiles", "Mango Sticky Rice", "Ragu", "Beef Brisket", 
              "Tortilla Española", "Panzanella", "Chicken Shawarma", "Pesto Pasta", "Bulgogi", "Maki Sushi", 
              "Cordon Bleu", "Blini with Caviar", "Clafoutis", "Salmon Teriyaki", "Shrimp Scampi", "Frittata", 
              "Chateaubriand", "Crab Cakes", "Chicken Fried Rice", "Hot Pot", "Mole Poblano", "Tofu Scramble"]

    restaurant_names = [
    "Golden Spoon Diner", "Sunset Bistro", "Blue Lagoon Cafe",
    "Mama Mia's Kitchen", "The Hungry Bear", "Skyline Tavern",
    "Crimson Oak Steakho", "The Velvet Fork", "Crescent Moon Caf",
    "Silver Star Eatery", "Harborview Grill", "Rustic Roots Kitch",
    "The Cozy Table", "Willow's Bistro", "Fire & Smoke BBQ",
    "Urban Harvest", "Hidden Gem Diner", "Maple Grove Cafe",
    "The Sizzling Skille", "Summit View Tavern", "Eclipse Bar & Gril",
    "Morning Dew Cafe", "The Rusty Spoon", "Emerald Coast Bistr",
    "Luna's Tacos & Tequ", "The Wandering Fork", "Hickory Hills BBQ",
    "Oak & Stone Eatery", "The Golden Lantern", "Bayside Grill",
    "Savory Seasons Kitc", "The Lazy Pelican", "Redwood Bistro",
    "The Blooming Table", "Aspen Heights Cafe", "Twilight Tavern",
    "The Daily Dish", "Sweetwater Bar & Gr", "Ironwood Kitchen",
    "Coastal Breeze Eate", "The Midnight Diner", "Golden Harvest Bis",
    "The Roaring Grill", "Prairie Sun Cafe", "Vineyard View Taver",
    "The Rustic Fork", "The Dancing Pine", "Sunflower Eatery",
    "The Wild Thyme", "Crave Kitchen & Bar", "The Clover Leaf Caf",
    "Pinecrest Bistro", "Sapphire Sky Gril", "The Hungry Moose",
    "Cedar Ridge Eatery", "Rosewood Cafe", "The Laughing Trout",
    "The Crimson Clover", "Copper Pot Kitchen", "Bluebird Bistro",
    "The Iron Skillet", "Pebble Shore Taver", "The Whistling Kett",
    "Mountain View Cafe", "Silver Birch Gril", "Seaside Eats",
    "The Rolling Pin", "The Rustic Rail", "Amber Waves Eatery",
    "The Lucky Spruce", "Harvest Moon Cafe", "The Salty Anchor",
    "The Wooden Table", "Meadowlark Bistro", "Golden Horizon Dine",
    "Red Maple Tavern", "Summit Ridge Cafe", "The Wandering Elk",
    "Crimson Flame Gril", "Lavender & Thyme C", "The Riverbend Tave",
    "Copperfield's Kitc", "Shoreline Bistro", "The Velvet Vine",
    "Blue Horizon Eater", "The Smoky Cedar", "Misty Ridge Cafe",
    "The Golden Trout", "Cozy Hearth Bistro", "The Frosty Mug",
    "Sunrise Kitchen", "Riverside Grill", "The Rustic Barrel",
    "Autumn Breeze Eate", "The Midnight Fork", "Spruce & Sage Tave",
    "Evergreen Bistro", "The Tasty Table", "Golden Valley Kitch"
]




    user_password = hashed_password = generate_password_hash("password")

    for _ in range(10):
        user_pk = str(uuid.uuid4())
        user_verified_at = random.choice([0, int(time.time())])
        user = {
            "user_pk": user_pk,
            "user_name": random.choice(restaurant_names),
            "user_last_name": "",
            "user_email": fake.unique.email(),
            "user_password": user_password,
            "user_created_at": int(time.time()),
            "user_deleted_at": 0,
            "user_blocked_at": 0,
            "user_updated_at": 0,
            "user_verified_at": user_verified_at,
            "user_verification_key": str(uuid.uuid4()),
            "user_reset_password_key": 0
        }
        insert_user(user)

        cursor.execute("""
        INSERT INTO users_roles (
            user_role_user_fk,
            user_role_role_fk)
            VALUES (%s, %s)
        """, (user_pk, x.RESTAURANT_ROLE_PK))

        # Randomly select 6 unique dishes per restaurant
        restaurant_dishes = random.sample(dishes, 6)  
        for dish in restaurant_dishes:
            dish_id = str(random.randint(1, 100))
            cursor.execute("""
            INSERT INTO items (
                item_pk, item_user_fk, item_title, item_price, item_image_1, item_image_2, item_image_3, item_created_at, item_deleted_at, item_blocked_at, item_updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                str(uuid.uuid4()),
                user_pk,
                dish,
                round(random.uniform(500, 999), 2),
                f"dish_{dish_id}.jpg",  # item_image_1
                f"dish_{dish_id}.jpg",  # item_image_2
                f"dish_{dish_id}.jpg",  # item_image_3
                int(time.time()),      # item_created_at
                0,                     # item_deleted_at
                0,                     # item_blocked_at
                0                      # item_updated_at
            ))

    db.commit()

except Exception as ex:
    ic(ex)
    if "db" in locals(): db.rollback()

finally:
    if "cursor" in locals(): cursor.close()
    if "db" in locals(): db.close()