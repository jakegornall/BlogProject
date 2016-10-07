from google.appengine.ext import db


class Users(db.Model):
    '''stores user login data'''
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)  # stored as hash
    email_address = db.EmailProperty(required=True)
    salt = db.IntegerProperty(required=True)  # for password validation

    @classmethod
    def by_name(cls, name):
        '''takes in username. Returns user's data'''
        u = Users.all().filter('username =', name).get()
        return u