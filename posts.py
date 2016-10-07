from google.appengine.ext import db


class BlogPosts(db.Model):
    '''stores all user's blog posts'''
    title = db.TextProperty(required=True)
    post = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    userID = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    likes = db.ListProperty(int)