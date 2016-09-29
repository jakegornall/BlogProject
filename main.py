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
SECRET = "87412356489266"# Key for hashing
########################## 

def make_salt():
    return random.randint(10000,99999)

def make_pass_hash(keyword, salt):
    return str(hashlib.sha256(str(keyword) + str(salt)).hexdigest())

def make_cookie_hash(cookie):
    return str(hashlib.sha256(str(cookie) + SECRET).hexdigest())

def make_cookie(cookie):
    return str(cookie) + "|" + make_cookie_hash(cookie)

def check_cookie(cookie):
    (cookieVal,hashStr) = cookie.split('|')
    if make_cookie_hash(cookieVal) == hashStr:
        return cookieVal
    else:
        return None



# DATABASE ENTITIES
############################################################
########################
### Blog Posts Entity ###
########################
class BlogPosts(db.Model):
    title = db.TextProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

####################
### Users Entity ###
####################
class Users(db.Model):
    username = db.TextProperty(required=True)
    password = db.TextProperty(required=True) # stored as hash
    salt = db.IntegerProperty(required=True) # for password validation
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
### Home Page Handler ###
#########################
class MainPage(Handler):
    def render_main(self, posts="", username=""):
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

        posts = db.GqlQuery("select * from BlogPosts order by created desc")
        self.render("home.html", posts=posts, username=username)

    def get(self):
        self.render_main()

##############################
### New Entry Page Handler ###
##############################
class NewEntry(Handler):
    def render_main(self, error="", username=""):
        self.render("newEntry.html", error=error, username=username)

    def get(self):
        userID = check_cookie(self.request.cookies.get("userID"))
        username = None
        if userID != None:
            user_key = db.Key.from_path('Users', long(userID))
            user = db.get(user_key)
            username = user.username
        self.render_main(username=username)

    def post(self):
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
            new_post = BlogPosts(title=title, post=post)
            new_post.put()
            time.sleep(1) # allows time for new db entry to post
            self.redirect('/')

############################
### Sign Up Page Handler ###
############################
class SignUpPage(Handler):
    def render_main(self, username="", error="", users=""):
        self.render("signup.html", username=username, error=error, users=users)

    def get(self):
        self.render_main()

    def post(self):
        salt = make_salt()
        username = self.request.get("username")
        password = self.request.get("password")
        users = db.GqlQuery("SELECT * FROM Users")
        all_usernames = []
        for x in users:
            all_usernames.append(x.username)
        passwordHashed = make_pass_hash(password, salt)
        

        if not username and not password:
            error = "username and password required"
            self.render_main(error=error)
        elif username and not password:
            error = "password required"
            self.render_main(error=error)
        elif not username and password:
            error = "username required"
            self.render_main(error=error)
        elif username in all_usernames:
            error = "username already exists"
            self.render_main(error=error)
        else:
            user = Users(username=username, password=passwordHashed, salt=salt)
            user.put()
            time.sleep(1)
            q = Users.all()
            user = []
            for x in q:
                if x.username == username:
                    user.append(x.key().id())
                    break
            userID = user[0]
            self.response.headers.add_header('Set-Cookie', 'userID=%s' % make_cookie(userID))
            self.redirect('/')



##########################################################################
        
### Maps URLs to Handlers ###
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newEntry', NewEntry),
    ('/signup', SignUpPage)
], debug=True)
