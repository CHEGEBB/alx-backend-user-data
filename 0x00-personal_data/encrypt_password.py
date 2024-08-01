#!/usr/bin/env python3
"""This function uses bcrypt to encrypt passwords.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """It hashes a password with bcrypt using a salt.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """This function checks if a password is valid oand if it has been hashed.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)