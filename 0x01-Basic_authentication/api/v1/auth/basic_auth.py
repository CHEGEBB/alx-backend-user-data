#!/usr/bin/env python3
""" Auth module
    Class BasicAuth that inherits from Auth
"""

from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """ BasicAuth class
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ extract_base64_authorization_header
        """
        type_check = type(authorization_header)
        if authorization_header is None or type_check is not str:
            return None
        if authorization_header[:6] != 'Basic ':
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ decode_base64_authorization_header
        """
        import base64
        type_check = type(base64_authorization_header)
        if base64_authorization_header is None or type_check is not str:
            return None
        try:
            base64_bytes = base64_authorization_header.encode('utf-8')
            message_bytes = base64.b64decode(base64_bytes)
            message = message_bytes.decode('utf-8')
            return message
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """ extract_user_credentials
        """
        type_check = type(decoded_base64_authorization_header)
        base64_decoded = decoded_base64_authorization_header
        if base64_decoded is None or type_check is not str:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user_credentials = base64_decoded.split(':', 1)
        return user_credentials[0], user_credentials[1]

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
            ) -> TypeVar('User'):
        """ user_object_from_credentials
        """
        # if user_email is None or type(user_email) is not str:
        #     return None
        # if user_pwd is None or type(user_pwd) is not str:
        #     return None
        # from models.user import User
        # search_user = User.search({'email': user_email})
        # if search_user is None or search_user == []:
        #     return None
        # for user in search_user:
        #     if user.is_valid_password(user_pwd):
        #         return user
        # return None
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        if request is None:
            return None
        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None
        base64_header = self.extract_base64_authorization_header(auth_header)
        if base64_header is None:
            return None
        b64 = base64_header
        decoded_base64_header = self.decode_base64_authorization_header(b64)
        if decoded_base64_header is None:
            return None
        user_credentials = self.extract_user_credentials(decoded_base64_header)
        if user_credentials[0] is None or user_credentials[1] is None:
            return None
        user = self.user_object_from_credentials(user_credentials[0],
                                                 user_credentials[1])
        return user

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """ extract_user_credentials
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if ':' not in decoded_base64_authorization_header:
            return None, None
        user_credentials = decoded_base64_authorization_header.split(':', 1)
        return user_credentials[0], user_credentials[1]
