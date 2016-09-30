#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import time
import re
import jinja2
import webapp2
from google.appengine.ext import db
import hashlib
import random


### sets up jinja2 environment ###
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

### Global Variables/Procedures ###
########################## 
SECRET = "87412356489266"# Key for hashing cookies
########################## 

################################### Host URL
hostURL = "http://localhost:8080" # update before deploying site
###################################

### email validation regular expression
email_re = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

def make_salt():
    return random.randint(10000,99999)

def make_pass_hash(keyword, salt):
    return str(hashlib.sha256(str(keyword) + str(salt)).hexdigest())

def make_cookie_hash(cookie):
    return str(hashlib.sha256(str(cookie) + SECRET).hexdigest())

def make_cookie(cookie):
    return str(cookie) + "|" + make_cookie_hash(cookie)

def check_cookie(cookie):
    if cookie:
        (cookieVal,hashStr) = cookie.split('|')
    else:
        return None
    if make_cookie_hash(cookieVal) == hashStr:
        return cookieVal
    else:
        return None

def valid_email(email_address):
    return email_re.match(email_address)



# DATABASE ENTITIES
############################################################
########################
### Blog Posts Entity ###
########################
class BlogPosts(db.Model):
    title = db.TextProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    userID = db.IntegerProperty(required=True)
    username = db.TextProperty(required=True)

####################
### Users Entity ###
####################
class Users(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True) # stored as hash
    email_address = db.EmailProperty(required=True)
    salt = db.IntegerProperty(required=True) # for password validation

    @classmethod
    def by_id(cls, uid):
        return Users.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = Users.all().filter('username =', name).get()
        return u

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
###########################################################

### helper procedures for page handlers ###
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# PAGE HANDLERS
############################################################################
#########################
### Feed Page Handler ###
#########################
class FeedPage(Handler):
    def render_main(self, posts="", username=""):
        userIDcookie = self.request.cookies.get("userID")
        userID = check_cookie(userIDcookie)
        username = None

        # if browser does not contain a userID cookie
        # redirect to the signup page
        if userID:
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
            posts = db.GqlQuery("SELECT * FROM BlogPosts ORDER BY created DESC")
            self.render("feed.html", posts=posts, username=username, hostURL=hostURL)
        else:
            self.redirect('/signin')

        

    def get(self):
        self.render_main()

#########################
### Home Page Handler ###
#########################
class MainPage(Handler):
    def render_main(self, posts="", username=""):
        userIDcookie = self.request.cookies.get("userID")
        userID = check_cookie(userIDcookie)
        username = None

        # if browser does not contain a userID cookie
        # redirect to the signup page
        if userID:
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
            posts = db.GqlQuery("SELECT * FROM BlogPosts WHERE userID=%s ORDER BY created DESC" % int(userID))
            self.render("home.html", posts=posts, username=username, hostURL=hostURL)
        else:
            self.redirect('/signin')

        

    def get(self):
        self.render_main()

##############################
### New Entry Page Handler ###
##############################
class NewEntry(Handler):
    def render_main(self, error="", username=""):
        self.render("newEntry.html", error=error, username=username, hostURL=hostURL)

    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = ""
        username = None
        
        # if browser does not contain a userID cookie
        # redirect to the signup page
        if userIDcookie != None:
            userID = check_cookie(userIDcookie)
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
        else:
            self.redirect('/signup')
        self.render_main(username=username)

    def post(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = ""
        username = None
        
        # if browser does not contain a userID cookie
        # redirect to the signup page
        if userIDcookie != None:
            userID = check_cookie(userIDcookie)
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
        else:
            self.redirect('/signup')

        title = self.request.get("subject")
        post = self.request.get("content")
        title = title.replace('/n','<br>')

        if not title and not post:
            error = "must enter a title and post!"
            self.render_main(error=error)
        elif title and not post:
            error = "must enter a post!"
            self.render_main(error=error)
        elif not title and post:
            error = "must enter a title!"
            self.render_main(error=error)
        else:
            new_post = BlogPosts(title=title, post=post, userID=int(userID), username=username)
            new_post.put()
            time.sleep(1) # allows time for new db entry to post
            self.redirect('/')

############################
### Sign In Page Handler ###
############################
class SignInPage(Handler):
    def render_main(self, username="", error="", users=""):
        self.render("signin.html", username=username, error=error, users=users, hostURL=hostURL)

    def get(self):
        self.render_main()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        user = Users.by_name(username)
        if user:
            passwordHash = user.password
            userSalt = user.salt
            userID = user.key().id()
        
        # handles user input on signin form:
        if not username and not password:
            error = "username and password required"
            self.render_main(error=error)
        elif username and not password:
            error = "password required"
            self.render_main(error=error)
        elif not username and password:
            error = "username required"
            self.render_main(error=error)
        elif not user:
            error = "username does not exists"
            self.render_main(error=error)
        elif passwordHash != make_pass_hash(password, userSalt):
            error = "incorrect password"
            self.render_main(error=error)
        else:
            self.response.headers.add_header('Set-Cookie', 'userID=%s' % make_cookie(userID))
            self.redirect('/')


############################
### Sign Up Page Handler ###
############################
class SignUpPage(Handler):
    def render_main(self,
                    username="",
                    usernameError="",
                    passwordError="",
                    verifyError="",
                    emailError="",
                    users="",
                    usernameVal=""):
        self.render("signup.html",
                    username=username,
                    usernameError=usernameError,
                    passwordError=passwordError,
                    verifyError=verifyError,
                    emailError=emailError,
                    users=users,
                    hostURL=hostURL,
                    usernameVal=usernameVal)

    def get(self):
        self.render_main()

    def post(self):
        salt = make_salt()
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        users = db.GqlQuery("SELECT * FROM Users")
        all_usernames = []
        usernameError = ""
        passwordError = ""
        verifyError = ""
        emailError = ""

        # as website scales this would need to change
        # to use either a db query or index.
        for x in users:
            all_usernames.append(x.username)
        passwordHashed = make_pass_hash(password, salt)
        
        # handles user input on signup form:
        if not username:
            usernameError = "username required!"
        if not password:
            passwordError = "password required!"
        if not verify:
            verifyError = "please verify password!"
        if not email:
            emailError = "email required!"
        if valid_email(email) == None:
            emailError = "invalid email address!"
        if password != verify:
            verifyError = "passwords do not match!"
        if username in all_usernames:
            usernameError = "username already exists"
        if usernameError or passwordError or verifyError or emailError:
            self.render_main(usernameError=usernameError,
                             passwordError=passwordError,
                             verifyError=verifyError,
                             emailError=emailError,
                             usernameVal=username)
        else:
            user = Users(username=username, password=passwordHashed, email_address=email, salt=salt)
            user.put()
            time.sleep(1)
            userID = user.key().id()
            self.response.headers.add_header('Set-Cookie', 'userID=%s' % make_cookie(userID))
            self.redirect('/')

##############################
### Edit Post Page Handler ###
##############################
class EditPost(Handler):
    def render_main(self, posts="", username=""):
        userIDcookie = self.request.cookies.get("userID")
        userID = check_cookie(userIDcookie)
        username = None

        # if browser does not contain a userID cookie
        # redirect to the signup page
        if userID:
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
            postID = self.request.get("postID")
            post = BlogPosts.get_by_id(int(postID))
            self.render("editpost.html", post=post, username=username, hostURL=hostURL)
        else:
            self.redirect('/signin')

        
    def get(self):
        self.render_main()

    def post(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = check_cookie(userIDcookie)
        username = None
        postID = self.request.get("postID")
        post_userID = BlogPosts.get_by_id(int(postID)).userID

        # if browser does not contain a userID cookie
        # redirect to the signup page
        if userID or userID != post_userID:
            userID = check_cookie(userIDcookie)
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
        else:
            self.redirect('/signup')

        title = self.request.get("subject")
        post = self.request.get("content")
        

        if not title and not post:
            error = "must enter a title and post!"
            self.render_main(error=error)
        elif title and not post:
            error = "must enter a post!"
            self.render_main(error=error)
        elif not title and post:
            error = "must enter a title!"
            self.render_main(error=error)
        else:
            blogEntry = BlogPosts.get_by_id(int(postID))
            blogEntry.title = title
            blogEntry.post = post
            blogEntry.put()
            time.sleep(1) # allows time for new db entry to post
            self.redirect('/')




######################################################
### DB control Page Handler (for development only) ###
######################################################
class DBpage(Handler):
    def get(self):
        users = Users.all()
        blogposts = BlogPosts.all()
        self.render("db.html", users=users, blogposts=blogposts, hostURL=hostURL)

    def post(self):
        usersCheck = self.request.get("users")
        postsCheck = self.request.get("posts")
        users = Users.all()
        blogposts = BlogPosts.all()
        userKeys = []
        postKeys = []
        for user in users:
            userKeys.append(user.key())
        for post in blogposts:
            postKeys.append(post.key())

        if usersCheck:
            db.delete(userKeys)
        if postsCheck:
            db.delete(postKeys)

        time.sleep(2)

        users = Users.all()
        blogposts = BlogPosts.all()
        self.render("db.html", users=users, blogposts=blogposts, hostURL=hostURL)

######################
### Logout Handler ###
######################
class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'userID=')
        self.redirect('/signup')



##########################################################################
        
### Maps URLs to Handlers ###
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newEntry', NewEntry),
    ('/signup', SignUpPage),
    ('/db', DBpage),
    ('/logout', Logout),
    ('/signin', SignInPage),
    ('/feed', FeedPage),
    ('/edit', EditPost)
], debug=True)
