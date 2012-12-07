from google.appengine.ext import db

class Poem(db.Model): 
    title = db.StringProperty(required=True) 
    text = db.TextProperty(required=True)
    page = db.StringProperty(required=False)
    written = db.StringProperty(required=False)
    created = db.DateTimeProperty(auto_now_add = True)
    
class User(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty(required=False)
    user_class = db.CategoryProperty(required=True)
    created = db.DateTimeProperty(auto_now_add = True)
    
class Error():
    name_error = ''
    pwd_error = ''
    ver_error = ''
    email_error = ''
    error = False
    
