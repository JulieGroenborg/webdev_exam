import requests
from icecream import ic
import math 
import inspect
import x

# Define the base URL of the API
BASE_URL = "http://127.0.0.1"  # Replace with your API base URL


def ok(message): print(f"\033[32m{message}\033[0m")
def error(message): print(f"\033[90m{message}\033[0m")
def warning(message): print(f"\033[33m{message}\033[0m")


def run_all_except_exclusions(exclusions):
    # Iterate over all items in the global namespace
    for name, func in globals().items():
        # Check if it's a function and not in the exclusions list
        if inspect.isfunction(func) and name not in exclusions:
            print(f"{name}")
            func()  # Call the function

routes = 0
passed = 0
failed = 0

def test(rule):
    global routes, passed, failed
    routes += 1

    if rule["method"].upper() == "GET":
        warning(rule["method"].upper())
        response = requests.get(f"{BASE_URL}{rule['url']}")

    if rule["method"].upper() == "POST":
        warning(rule["method"].upper())
        response = requests.post(f"{BASE_URL}{rule['url']}", data=rule["data"])

    # Check if the response status code is 200 OK
    if rule.get("status_code"):
        message = f"{response}"
        if response.status_code == rule.get("status_code"):
            passed += 1
            ok(message)
        else:
            failed += 1
            error("----- " + message)
            error(response.text)
    
    # Check if the response is a JSON object
    if rule.get("is_json"):
        message = "Content-Type is JSON"
        if 'application/json; charset=utf-8'.lower() in response.headers.get('Content-Type').lower():
            passed += 1
            ok(message)
        else:
            failed += 1
            error("----- " + message)
            error(response.text)   

    if rule.get("is_html"):
        content_type = response.headers.get('Content-Type')
        message = f"Content-Type is {content_type}"
        if 'text/html; charset=UTF-8'.lower() in response.headers.get('Content-Type').lower():
            passed += 1
            ok(message)
        else:
            failed += 1
            error("----- " + message)
            error(response.text)             

    if rule.get("contains"):
        for contain in rule.get("contains"):
            message = f"Response contains {contain}"
            if contain in response.text:
                passed += 1
                ok(message)
            else:
                failed += 1
                error("----- " + message)  
                error(response.text)     


    data = response.text
    # print(data)
    print()



def ___________signup__________(): pass


def signup_no_user_name():
    test({
        "method":"POST",
        "data":{},        
        "url":"/users",
        "status_code" : 400,
        "contains": ["name"]
    })

def signup_invalid_user_name_min():
    test({
        "method":"POST",
        "data":{
            "user_name":"a"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["name", str(x.USER_LAST_NAME_MIN)]
    })

def signup_invalid_user_name_max():
    test({
        "method":"POST",
        "data":{
            "user_name":"a"*30
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["name", str(x.USER_LAST_NAME_MAX)]
    })


def signup_no_user_last_name():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["last name"]
    })

def signup_invalid_user_last_name_min():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"b"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["last name", str(x.USER_LAST_NAME_MIN)]
    })    


def signup_invalid_user_last_name_max():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"b"*30
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["last name", str(x.USER_LAST_NAME_MAX)]
    })    

def signup_no_user_email():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["email"]
    })

def signup_invalid_email():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
            "user_email":"a@"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["email invalid"]
    })


def signup_no_password():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
            "user_email":"a@a.com"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["password"]
    })


def signup_invalid_password_min():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
            "user_email":"a@a.com",
            "user_password":"a"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["password", str(x.USER_PASSWORD_MIN)]
    })


def signup_invalid_password_max():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
            "user_email":"a@a.com",
            "user_password":"a"*100
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["password", str(x.USER_PASSWORD_MAX)]
    })


def signup_success():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
            "user_email":"xxx@xx.com",
            "user_password":"password"
        },        
        "url":"/users",
        "status_code" : 201,
        "contains": ["login"]
    })    


def signup_email_already_registered():
    test({
        "method":"POST",
        "data":{
            "user_name":"Aa",
            "user_last_name":"Bb",
            "user_email":"xx@xx.com",
            "user_password":"password"
        },        
        "url":"/users",
        "status_code" : 400,
        "contains": ["email"]
    })   


def ___________login__________(): pass

def login_email_no():
    test({
        "method":"POST",
        "data":{
        },        
        "url":"/login",
        "status_code" : 400,
        "contains": ["email"]
    })  

def login_email_invalid():
    test({
        "method":"POST",
        "data":{
            "user_email":"a@",
        },        
        "url":"/login",
        "status_code" : 400,
        "contains": ["email"]
    })            

def login_password_no():
    test({
        "method":"POST",
        "data":{
            "user_email":"a@a.com"
        },        
        "url":"/login",
        "status_code" : 400,
        "contains": ["password"]
    })   

def login_password_min():
    test({
        "method":"POST",
        "data":{
            "user_email":"a@a.com",
            "user_password":"p"
        },        
        "url":"/login",
        "status_code" : 400,
        "contains": ["password", str(x.USER_PASSWORD_MIN)]
    })   


def login_password_max():
    test({
        "method":"POST",
        "data":{
            "user_email":"a@a.com",
            "user_password":"p"*100
        },        
        "url":"/login",
        "status_code" : 400,
        "contains": ["password", str(x.USER_PASSWORD_MAX)]
    })  


def login_credentials():
    test({
        "method":"POST",
        "data":{
            "user_email":"a@a.com",
            "user_password":"passwordx"
        },        
        "url":"/login",
        "status_code" : 401,
        "contains": ["credentials"]
    })      


def login_success():
    test({
        "method":"POST",
        "data":{
            "user_email":"a@a.com",
            "user_password":"password"
        },        
        "url":"/login",
        "status_code" : 200,
        "contains": ["redirect"]
    }) 





# Run all functions except the excluded ones
# login_email_invalid()
run_all_except_exclusions(["ok", "error", "warning", "run_all_except_exclusions", "test"])



warning(f"Routes tested\t\t{routes}")
ok(f"Passed\t\t\t{passed}")
if failed == 0:
    error(f"Failed\t\t\t{failed}")
else:
    print(f"Failed\t\t\t\033[91m{failed}\033[0m")
print()
print()








rules = [



    {
    "name":"Check main site",
    "test": True,
    "method":"GET",
    "url":"/",
    "status_code" : 200,
    "is_json": False,
    "is_html": True,
    "contains": ["<title>"]
    },


    {
    "name":"view login",
    "test": True,
    "method":"GET", 
    "url":"/login",
    "status_code" : 200,
    "is_json": False,
    "is_html": True,
    "contains": ["<title>"]
    },
    

    {
    "name":"signup user - user_name missing",
    "test": True,
    "method":"POST",
    "data":{},        
    "url":"/users",
    "status_code" : 400,
    "contains": ["name"]
    },   


    {
    "name":"signup user - user_last_name missing",
    "test": True,
    "method":"POST",
    "data":{
        "user_name":"Aa"
    },        
    "url":"/users",
    "status_code" : 400,
    "contains": ["last name"]
    },   


    {
    "name":"signup user - user_email missing",
    "test": True,
    "method":"POST",
    "data":{
        "user_name":"Aa",
        "user_last_name":"Bb"
    },        
    "url":"/users",
    "status_code" : 400,
    "contains": ["email"]
    },      


    {
    "name":"signup user - user_passsword missing",
    "test": True,
    "method":"POST",
    "data":{
        "user_name":"Aa",
        "user_last_name":"Bb",
        "user_email":"aa@bb.com"
    },        
    "url":"/users",
    "status_code" : 400,
    "contains": ["password"]
    },   


    {
    "name":"signup user",
    "test": True,
    "method":"POST",
    "data":{
        "user_name":"Aa",
        "user_last_name":"Bb",
        "user_email":"aax@bb.com",
        "user_password":"password"
    },        
    "url":"/users",
    "status_code" : 200,
    "contains": ["template"]
    },  


    {
    "name":"signup user - email already in use",
    "test": True,
    "method":"POST",
    "data":{
        "user_name":"Aa",
        "user_last_name":"Bb",
        "user_email":"aax@bb.com",
        "user_password":"password"
    },        
    "url":"/users",
    "status_code" : 400,
    "contains": ["template"]
    },  


    {
    "name":"login user incorrect email and password",
    "test": True,
    "method":"POST",
    "data":{
        "user_email" : "no@a.com",
        "user_password": "password1",
    },        
    "url":"/login",
    "status_code" : 400,
    "is_json": False,
    "is_html": True,
    "contains": ["</template>"]
    },   



    {
        "name":"login user incorrect password",
        "test": True,
        "method":"POST",
        "data":{
            "user_email" : "a@a.com",
            "user_password": "password1",
        },        
        "url":"/login",
        "status_code" : 401,
        "is_json": False,
        "is_html": True,
        "contains": ["</template>"]
    },   

    # {
    # "name":"get_item.py",
    # "test": True,
    # "method":"GET",
    # "url":"/items/1",
    # "status_code" : 200,
    # "is_json": False,
    # "is_html": True,
    # "contains": ["x", "</template>"]
    # },



    # {
    # "name":"get_more_items.py",
    # "test": True,
    # "method":"GET",
    # "url":"/page/1",
    # "status_code" : 200,
    # "is_json": False,
    # "is_html": True,
    # "contains": ["x", "</template>"]
    # },    

    ##############################
    ##### POST #####



    # {
    # "name":"login",
    # "test": True,
    # "method":"POST",
    # "url":"/login",
    # "data":{
    #     "user_email" : "a@a.com",
    #     "user_password": "password",
    # },
    # "status_code" : 200,
    # "is_json": False,
    # "is_html": True,
    # "contains": ["</template>"]
    # },   



    # {
    #     "name":"post_signup.py",
    #     "test": False,
    #     "method":"POST",
    #     "url":"/users",
    #     "data":{
    #         "user_email":"a@a.com",
    #         "user_password":"password",
    #     },
    #     "status_code" : 200,
    #     "is_json": False,
    #     "is_html": True,
    #     "contains": ["</template>", "mix-redirect"]
    # },    

       
]


"""
routes = 0
passed = 0
failed = 0
for rule in rules:
    if not rule.get("test", False):
        continue
    routes += 1
    print("#"*10)
    print(rule["name"])

    if rule["method"].upper() == "GET":
        warning(rule["method"].upper())
        response = requests.get(f"{BASE_URL}{rule['url']}")

    if rule["method"].upper() == "POST":
        warning(rule["method"].upper())
        response = requests.post(f"{BASE_URL}{rule['url']}", data=rule["data"])

    # Check if the response status code is 200 OK
    if rule.get("status_code"):
        message = f"{response}"
        if response.status_code == rule.get("status_code"):
            passed += 1
            ok(message)
        else:
            failed += 1
            error("----- " + message)
            error(response.text)
    
    # Check if the response is a JSON object
    if rule.get("is_json"):
        message = "Content-Type is JSON"
        if 'application/json; charset=utf-8'.lower() in response.headers.get('Content-Type').lower():
            passed += 1
            ok(message)
        else:
            failed += 1
            error("----- " + message)
            error(response.text)   

    if rule.get("is_html"):
        content_type = response.headers.get('Content-Type')
        message = f"Content-Type is {content_type}"
        if 'text/html; charset=UTF-8'.lower() in response.headers.get('Content-Type').lower():
            passed += 1
            ok(message)
        else:
            failed += 1
            error("----- " + message)
            error(response.text)             

    if rule.get("contains"):
        for contain in rule.get("contains"):
            message = f"Response contains {contain}"
            if contain in response.text:
                passed += 1
                ok(message)
            else:
                failed += 1
                error("----- " + message)  
                error(response.text)     


    data = response.text
    # print(data)
    print()
print()
warning(f"Routes tested\t\t{routes}")
ok(f"Passed\t\t\t{passed}")
if failed == 0:
    error(f"Failed\t\t\t{failed}")
else:
    print(f"Failed\t\t\t\033[91m{failed}\033[0m")
print()
print()

"""

    



##############################
# def test_post_item():
#     """Test POST request to create an item."""
#     new_item = {'name': 'New Item'}
#     response = requests.post(f"{BASE_URL}/items", json=new_item)
    
#     # Check if the response status code is 201 Created
#     if response.status_code == 201:
#         print("POST /items: Passed")
#     else:
#         print(f"POST /items: Failed (Status Code: {response.status_code})")

#     # Check if the response returns the created item
#     created_item = response.json()
#     if 'id' in created_item:
#         print("Created item contains 'id': Passed")
#     else:
#         print("Created item does not contain 'id': Failed")


