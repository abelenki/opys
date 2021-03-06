import os
import webapp2
import jinja2
from python import random
from python import string
 
from hashlib import md5
from hashlib import sha256

from regex import re

from google.appengine.ext import db
from google.appengine.ext.webapp.util import run_wsgi_app

from entities import User
from entities import Poem
from entities import Error
from entities import Comment

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),autoescape=True)

USER = db.Category("user")
ADMIN = db.Category("admin")

#CONFIG: Change this to suit yourself
ADMINISTRATOR = 'administrator'
SITE_TITLE = "A Child of Hard Times"
SITE_SUBTITLE = "Poems by Bea Sisk"
COMMENT_SUBTITLE = "Comments"
COPYRIGHT_NOTICE = "&copy;Bea Sisk 2012 - All rights reserved, no wrongs deserved."

def hash_str(s):
    return md5(s).hexdgest()

def make_secure_val(s):
    return "%s,%s" % (s,hash_str(s))

def check_secure_val(h):
    val = h.split(",")[0]
    if h == make_secure_val(val):
        return val
    
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def hash_pw(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    return h == hash_pw(name, pw, salt)
    

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))
        
def getUser(username):
    users = db.GqlQuery("SELECT * FROM User where username = :1",username)
    user = None
    for u in users:
        user = u
        if user.username == username:
            break
    return user

def isAdmin(username):
    user = getUser(username)
    admin = False
    if not user == None and user.user_class == ADMIN:
        return True
    return False
             
class MainPage(Handler):
    def get(self):
        self.render_index()
        
    def post(self):
        title = self.request.get("title")
        text = self.request.get("text")
        key = self.request.get("key")
        page = self.request.get("page")
        written = self.request.get("written")
        if key and title and text:
            a = db.get(key)
            a.title = title
            a.text = text
            if page == None:
                a.page = ''
            else:
                a.page = page
            if written == None:
                a.written=''
            else:
                a.written = written            
            db.save(a)
            self.redirect("/")
        elif title and text:
            a = Poem(title=title, text=text, page=page, written=written)
            a.put()
            self.redirect("/")
        else:
            error = "incomplete submission"
            poem = Poem(title=title,text=text,page=page,written=written)
            self.render_index(poem, error,"")
            
    def render_index(self,poem = None,user_id = None):
        poems = db.GqlQuery("select * from Poem order by page asc, created desc")
        user_id = self.request.cookies.get("user-id")
        admin = isAdmin(user_id)
        self.render("index.html", poem=poem,poems=poems,user_id=user_id,admin=admin,
                    site_title=SITE_TITLE, site_subtitle=SITE_SUBTITLE, copyright_notice = COPYRIGHT_NOTICE)
        
class DeleteHandler(Handler): 
    def post(self):
        key=self.request.get("key")     
        poem= db.get(key)
        poem.delete()
        self.redirect("/")

class EditHandler(Handler):
    def post(self):       
        poems = db.GqlQuery("select * from Poem order by page asc, created desc")
        key = self.request.get("key")
        poem = db.get(key)
        user_id = self.request.cookies.get("user-id")
        admin = isAdmin(user_id)
        self.render("index.html", poem = poem, poems=poems, key=key, user_id = user_id, admin=admin,
                    site_title=SITE_TITLE, site_subtitle=SITE_SUBTITLE, copyright_notice=COPYRIGHT_NOTICE)
        
class LoginHandler(Handler):
    def get(self):
        self.render("login.html",site_title=SITE_TITLE, site_subtitle=SITE_SUBTITLE)
   
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = getUser(username)
        if not user == None and valid_pw(username, password, user.password):
            self.response.headers.add_header('Set-Cookie','user-id=' + username)
            self.redirect("/")
        else:
            self.render("login.html",username=username,login_error="Invalid username or password",
                        site_title=SITE_TITLE, site_subtitle=SITE_SUBTITLE)
        
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','user-id=')
        self.redirect("/")
        
class CancelHandler(Handler):
    def get(self):
        self.redirect("/")
    def post(self):
        self.redirect("/")

class RegistrationHandler(Handler):
    def render_register(self,username="",password="",verify="",email="",error=None):
        self.render("registration.html", username=username, password=password, verify=verify, email=email,
                   error=error,site_title=SITE_TITLE, site_subtitle=SITE_SUBTITLE)
     
    def get(self):
        self.render_register()  
          
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        c_username = self.check(username, "^[a-zA-Z0-9_-]{3,20}$")
        c_password = self.check(password, "^.{3,20}$")
        c_email = self.check(email,"^[\S]+@[\S]+\.[\S]+$")   
        error = Error()
        user = getUser(username)
        if not user == None:
            error.name_error = "duplicate user name.  please choose another."
            error.error = True
        if(password != verify):
            error.ver_error = "Password does not match"
            error.error = True
        if c_username == None:
            error.name_error = "Invalid Username"
            error.error = True
        if c_password == None:
            error.pwd_error = "Invalid Password"
            error.error = True
        if(email != "" and c_email == None):
            error.email_error = "Invalid email address" 
            error.error = True   
        if error.error:   
            self.render_register(username, "", "", email,error)
        else :
            #save user in database
            user_class = USER
            if username == ADMINISTRATOR:
                user_class = ADMIN            
            user = User(username=username, password=hash_pw(username,password), email=email, user_class=user_class)
            user.put()
            #set login cookie
            #redirect to index page
            self.redirect('/')
        
    def check(self, field, pattern):
        RE = re.compile(pattern)
        return RE.match(field)

class CommentHandler(Handler):
    def render_comments(self, comment=None, key=None, error=None):
        poems = db.GqlQuery("select * from Poem order by page asc, created desc")
        comments = db.GqlQuery("select * from Comment order by created asc")
        user_id = self.request.cookies.get("user-id")  
        admin = isAdmin(user_id)                  
        self.render("comments.html",comment=comment, key = key, comments=comments,poems=poems,username=user_id,admin = admin,
                    error=error,site_title=SITE_TITLE, site_subtitle=COMMENT_SUBTITLE)
    def get(self):
        #display the comments page
        self.render_comments()

    def post(self):
        #persist new comment to the db and 
        title = self.request.get("title")
        text = self.request.get("text")
        key = self.request.get("key") 
        user_id = self.request.cookies.get("user-id")
        if key and title and text:
            comment = db.get(key)
            comment.title = title
            comment.text = text
            db.save(comment)
        elif title and text:
            comment = Comment(title=title,text=text,username=user_id)
            comment.put()
        self.redirect('/comments')

class EditCommentHandler(Handler):
    def post(self):
        key = self.request.get("key")
        comment = db.get(key)
        poems = db.GqlQuery("select * from Poem order by page asc, created desc")
        comments = db.GqlQuery("select * from Comment order by created asc")
        user_id = self.request.cookies.get("user-id")  
        admin = isAdmin(user_id)
        self.render("comments.html",comment=comment, key = key, comments=comments,poems=poems,username=user_id,admin = admin,
                    error=None,site_title=SITE_TITLE, site_subtitle=COMMENT_SUBTITLE)
        
    def get(self):
        key = self.request.get("key")
        comment = db.get(key)
        poems = db.GqlQuery("select * from Poem order by page asc, created desc")
        comments = db.GqlQuery("select * from Comment order by created asc")
        user_id = self.request.cookies.get("user-id") 
        admin = isAdmin(user_id)
        self.render("comments.html",comment=comment, key = key, comments=comments,poems=poems,username=user_id,admin = admin,
                    error=None,site_title=SITE_TITLE, site_subtitle=COMMENT_SUBTITLE)
    
class DeleteCommentHandler(Handler):
    def post(self):
        key = self.request.get("key")
        comment = db.get(key)
        db.delete(comment)
        self.redirect("/comments")
        
    def get(self):
        key = self.request.get("key")
        comment = db.get(key)
        db.delete(comment)
        self.redirect("/comments")
        
    
application = webapp2.WSGIApplication([('/', MainPage),
                                       ('/delete',DeleteHandler),
                                       ('/edit',EditHandler),
                                       ('/login',LoginHandler),
                                       ('/logout',LogoutHandler),
                                       ('/registration',RegistrationHandler),
                                       ('/cancel',CancelHandler),
                                       ('/comments',CommentHandler),
                                       ('/edit_comment',EditCommentHandler),
                                       ('/delete_comment',DeleteCommentHandler)
                                       ], debug=True)

def main():
    run_wsgi_app(application)

if __name__ == "__main__":
    main()
