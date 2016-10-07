from google.appengine.ext import db


class Comments(db.Model):
    '''Stores all comments on posts'''
    postID = db.IntegerProperty(required=True)
    userID = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    username = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)