from google.appengine.ext import db


class Comments(db.Model):
    '''Stores all comments on posts'''
    postID = db.IntegerProperty(required=True)
    userID = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)