class User(object):
    def __init__(self, username, password):
        self.__username = username
        self.__password = password

    def get_username(self):
        return self.__username

    def get_password(self):
        return self.__password

    def __repr__(self):
        return '<user: username=%s, password=%s>' % (self.get_username(), self.__password)


class UserManager(object):
    def __init__(self):
        self.__users = {}

    def add_user(self, user):
        self.__users[user.get_username()] = user

    def remove_user(self, username):
        if username in self.__users:
            del self.__users[username]

    def check(self, username, password):
        if username in self.__users and self.__users[username].get_password() == password:
            return True
        else:
            return False

    def get_user(self, username):
        return self.__users[username]

    def get_users(self):
        return self.__users

