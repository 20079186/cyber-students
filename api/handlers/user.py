from tornado.web import authenticated
from .auth import AuthHandler
from ..security import decrypt

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        initialization_vector = bytes.fromhex(self.current_user['initialization_vector'])

        self.set_status(200)
        self.response['email'] = decrypt(self.current_user['email'], initialization_vector)
        self.response['displayName'] = decrypt(self.current_user['display_name'], initialization_vector)
        self.response['fullName'] = decrypt(self.current_user['full_name'], initialization_vector)
        self.response['address'] = decrypt(self.current_user['address'], initialization_vector)
        self.response['dob'] = decrypt(self.current_user['dob'], initialization_vector)
        self.response['phoneNum'] = decrypt(self.current_user['phone_number'], initialization_vector)
        self.response['disabilities'] = decrypt(self.current_user['disabilities'], initialization_vector)
        self.write_json()
