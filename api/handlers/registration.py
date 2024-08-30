from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from .base import BaseHandler
from ..security import encrypt, kdf_hash, basic_hash
import os

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            full_name = body['fullName']
            if not isinstance(full_name, str):
                raise Exception()
            address = body['address']
            if not isinstance(address, str):
                raise Exception()
            dob = body['dob']
            if not isinstance(dob, str):
                raise Exception()
            phone_number = body['phoneNum']
            if not isinstance(phone_number, str):
                raise Exception()
            disabilities = body['disabilities']
            if not isinstance(disabilities, str):
                raise Exception()

        except Exception as e:
            self.send_error(400, message='You must provide an email address, password, display name, full name, address, date of birth, phone number and any disabilities!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        if not full_name:
            self.send_error(400, message='The full name is invalid!')
            return

        if not address:
            self.send_error(400, message='The address is invalid!')
            return
        
        if not dob:
            self.send_error(400, message='The date of birth is invalid!')
            return

        if not phone_number:
            self.send_error(400, message='The phone number is invalid!')
            return
        
        if not disabilities:
            self.send_error(400, message='The disabilities is invalid!')
            return

        user_by_email = yield self.db.users.find_one({
          'lookupEmail': basic_hash(email)
        }, {})

        if user_by_email is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        # Generating a random salt for the user's password.
        pass_salt = os.urandom(16)
        # Generating a random initialisation vector for the user.
        initialization_vector = os.urandom(16)
        # Hashing the user's password.
        hashed_password = kdf_hash(password, pass_salt)
        # Creating a simple hash of the email using a more basic hashing. This is finding the user in the database but still providing some security for the user's email.
        hashed_email = basic_hash(email)

        yield self.db.users.insert_one({
            'email': encrypt(email, initialization_vector),
            'lookupEmail': hashed_email,
            'displayName': encrypt(display_name, initialization_vector),
            'fullName': encrypt(full_name, initialization_vector),
            'address': encrypt(address, initialization_vector),
            'dob': encrypt(dob, initialization_vector),
            'phoneNum': encrypt(phone_number, initialization_vector),
            'disabilities': encrypt(disabilities, initialization_vector),
            'password': hashed_password,
            'passSalt': pass_salt.hex(),
            'initializationVector': initialization_vector.hex(),
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.response['fullName'] = full_name
        self.response['address'] = address
        self.response['dob'] = dob
        self.response['phoneNum'] = phone_number
        self.response['disabilities'] = disabilities

        self.write_json()
