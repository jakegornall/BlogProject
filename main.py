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

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

class BlogPosts(db.Model):
    title = db.TextProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


class MainPage(Handler):
    def render_main(self, posts="", error=""):
        posts = db.GqlQuery("select * from BlogPosts order by created desc")
        self.render("main.html", posts=posts, error=error)

    def get(self):
        self.render_main()

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
            self.redirect('/')
        

app = webapp2.WSGIApplication([
    ('/', MainPage)
], debug=True)
