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
from posts import *
from users import *
from comments import *

# Sets up jinja2 environment
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

#  Global Variables/Procedures
SECRET = "87412356489266"  # Key for hashing cookies

# Host URL
hostURL = "http://localhost:8080"  # update before deploying site

# email validation regular expression
email_re = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")  # Thank you, to http://emailregex.com/


def make_salt():
    '''creates randomly generated number
    for use in password hashing'''
    return random.randint(10000, 99999)


def make_pass_hash(keyword, salt):
    return str(hashlib.sha256(str(keyword) + str(salt)).hexdigest())


def make_cookie_hash(cookie):
    return str(hashlib.sha256(str(cookie) + SECRET).hexdigest())


def make_cookie(cookie):
    return str(cookie) + "|" + make_cookie_hash(cookie)


def check_cookie(cookie):
    if cookie:
        (cookieVal, hashStr) = cookie.split('|')
    else:
        return None
    return cookieVal if make_cookie_hash(cookieVal) == hashStr else None


def valid_email(email_address):
    '''uses globally defined regular expression
    to validate email address'''
    return email_re.match(email_address)


def validUser(userIDcookie):
    userID = check_cookie(userIDcookie)
    '''if userIDcookie does not exist or has been tampered with
    return None. If userIDcookie is valid, return userID'''
    if userID:
        return int(userID)
    else:
        return None


class Handler(webapp2.RequestHandler):
    '''Helper procedures for page handlers'''
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# PAGE HANDLERS
class FeedPage(Handler):
    '''Feed Page Handler'''
    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')
        else:
            user = Users.get_by_id(userID)
            username = user.username
            posts = db.GqlQuery('''SELECT *
                                FROM BlogPosts
                                ORDER BY created DESC''')
            comments = Comments.all()
            self.render("feed.html",
                        posts=posts,
                        comments=comments,
                        username=username,
                        userID=userID,
                        hostURL=hostURL)


class MainPage(Handler):
    '''Home Page Handler'''
    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')
        else:
            user = Users.get_by_id(userID)
            username = user.username
            posts = db.GqlQuery('''SELECT *
                                FROM BlogPosts
                                WHERE userID=%s
                                ORDER BY created DESC''' % userID)
            self.render("home.html",
                        posts=posts,
                        username=username,
                        hostURL=hostURL)


class NewEntry(Handler):
    '''New Entry Page Handler'''
    def render_main(self, error="", username=""):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')

        user = Users.get_by_id(userID)
        username = user.username
        self.render("newEntry.html",
                    error=error,
                    username=username,
                    hostURL=hostURL)

    def get(self):
        self.render_main()

    def post(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')

        user = Users.get_by_id(userID)
        username = user.username
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
            new_post = BlogPosts(title=title,
                                 post=post,
                                 userID=userID,
                                 username=username)
            new_post.put()
            time.sleep(1)  # allows time for new db entry to post
            return self.redirect('/')


class SignInPage(Handler):
    '''Sign In Page Handler'''
    def render_main(self, username="", error="", users=""):
        self.render("signin.html",
                    username=username,
                    error=error,
                    users=users,
                    hostURL=hostURL)

    def get(self):
        self.render_main()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        user = Users.by_name(str(username))
        if user:
            passwordHash = user.password
            userSalt = user.salt
            userID = user.key().id()

        # validates user input on signin form:
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
            self.response.headers.add_header('Set-Cookie',
                                             'userID=%s' % make_cookie(userID))
            return self.redirect('/')


class SignUpPage(Handler):
    '''Sign Up Page Handler'''
    def render_main(self,
                    username="",
                    usernameError="",
                    passwordError="",
                    verifyError="",
                    emailError="",
                    users="",
                    usernameVal=""):
        userIDcookie = self.request.cookies.get('userID')
        if validUser(userIDcookie):
            return self.redirect(hostURL)
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
        isUser = Users.by_name('username')
        all_usernames = []
        usernameError = ""
        passwordError = ""
        verifyError = ""
        emailError = ""
        passwordHashed = make_pass_hash(password, salt)

        # validates user input on signup form:
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
        if isUser:
            usernameError = "username already exists"
        if usernameError or passwordError or verifyError or emailError:
            self.render_main(usernameError=usernameError,
                             passwordError=passwordError,
                             verifyError=verifyError,
                             emailError=emailError,
                             usernameVal=username)
        else:
            user = Users(username=username,
                         password=passwordHashed,
                         email_address=email,
                         salt=salt)
            user.put()
            time.sleep(1)
            userID = user.key().id()
            self.response.headers.add_header('Set-Cookie',
                                             'userID=%s' % make_cookie(userID))
            return self.redirect('/')


class EditPost(Handler):
    '''Edit Post Page Handler'''
    def render_main(self, posts="", username=""):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')

        user = Users.get_by_id(userID)
        username = user.username
        postID = self.request.get("postID")
        post = BlogPosts.get_by_id(int(postID))
        post_userID = BlogPosts.get_by_id(int(postID)).userID

        if userID != post_userID:
            return self.redirect('/')
        self.render("editpost.html",
                    post=post,
                    username=username,
                    hostURL=hostURL)

    def get(self):
        self.render_main()

    def post(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)

        if not userID:
            return self.redirect('/signin')

        user = Users.get_by_id(userID)
        username = user.username
        username = None
        postID = self.request.get("postID")
        post_userID = BlogPosts.get_by_id(int(postID)).userID

        if userID != post_userID:
            return self.redirect('/')

        userID = check_cookie(userIDcookie)
        user_key = db.Key.from_path('Users', long(userID))
        user = db.get(user_key)
        username = user.username

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
            time.sleep(1)  # allows time for new db entry to post
            return self.redirect('/')


class SinglePostPage(Handler):
    '''Single Post Page Handler'''
    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')
        else:
            user = Users.get_by_id(userID)
            username = user.username
            postID = int(self.request.get("postID"))
            post = BlogPosts.get_by_id(postID)
            comments = Comments.all().filter('postID =', postID).order('created').run()
            self.render("post.html",
                        post=post,
                        comments=comments,
                        username=username,
                        userID=userID)

    def post(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')
        else:
            user = Users.get_by_id(userID)
            username = user.username

        postID = int(self.request.get("postID"))
        comment = self.request.get("new_comment")
        comment_submission = Comments(postID=postID,
                                      userID=userID,
                                      username=username,
                                      comment=comment)
        comment_submission.put()
        post = BlogPosts.get_by_id(postID)
        time.sleep(1)
        comments = Comments.all().filter('postID =', postID).order('created').run()
        self.render("post.html",
                    post=post,
                    comments=comments,
                    username=username,
                    userID=userID)


class Logout(Handler):
    '''Logout Page Handler'''
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'userID=')
        return self.redirect('/signup')


class DeletePost(Handler):
    '''Delete Post Handler'''
    def get(self):
        postID = self.request.get("postID")
        post_to_delete = BlogPosts.get_by_id(int(postID))
        post_userID = post_to_delete.userID
        currentUserID = int(check_cookie(self.request.cookies.get("userID")))
        if not currentUserID:
            return self.redirect('/')
        if currentUserID == post_userID:
            post_to_delete.delete()

        time.sleep(1)
        return self.redirect('/')


class EditComment(Handler):
    '''Handles Comment Edit Requests'''
    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        commenter_userID = int(self.request.get("commenter_userID"))
        if not userID:
            return self.redirect('%s/signin' % hostURL)
        elif userID != commenter_userID:
            return self.redirect(hostURL)
        else:
            commentID = int(self.request.get("commentID"))
            edited_comment = self.request.get("edited_comment")
            comment = Comments.get_by_id(commentID)
            postID = comment.postID
            comment.comment = edited_comment
            comment.put()
            time.sleep(1)
            return self.redirect('/permalink?postID=%s' % postID)




class DeleteComment(Handler):
    '''Handles Delete Comment Requests'''
    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        if not userID:
            return self.redirect('/signin')
        else:
            commentID = int(self.request.get("commentID"))
            commentObject = Comments.get_by_id(commentID)
            commenter_userID = commentObject.userID
            postID = commentObject.postID
            if userID != commenter_userID:
                return self.redirect('/')
            else:
                commentObject.delete()
                time.sleep(1)
                return self.redirect('/permalink?postID=%s' % postID)

class PostLike(Handler):
    '''Handles blog post like requests'''
    def get(self):
        userIDcookie = self.request.cookies.get("userID")
        userID = validUser(userIDcookie)
        postID = self.request.get("post-like")
        post = BlogPosts.get_by_id(int(postID))
        if not userID:
            return self.redirect('/signin')
        elif userID != post.userID:
            if userID in post.likes:
                post.likes.remove(userID)
                post.put()
                time.sleep(.2)
                return self.redirect('/feed')
            else:
                post.likes.append(userID)
                post.put()
                time.sleep(.2)
                return self.redirect('/feed')
        else:
            return self.redirect('/feed')

# Maps URLs to Handlers
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newEntry', NewEntry),
    ('/signup', SignUpPage),
    ('/logout', Logout),
    ('/signin', SignInPage),
    ('/feed', FeedPage),
    ('/edit', EditPost),
    ('/delete', DeletePost),
    ('/permalink', SinglePostPage),
    ('/postLike', PostLike),
    ('/deletecomment', DeleteComment),
    ('/editcomment', EditComment)
], debug=True)
