#!/usr/bin/env python3
"""Module to filter logs by obfuscating sensitive information.
"""

import os
import re
import logging
import mysql.connector
from typing import List

# Predefined regex patterns for extracting and replacing sensitive data
patterns = {
    'extract': lambda x, y: r'(?P<field>{})=[^{}]*'.format('|'.join(x), y),
    'replace': lambda x: r'\g<field>={}'.format(x),
}

# Fields that contain Personally Identifiable Information (PII)
PII_FIELDS = ("name", "email", "phone", "ssn", "password")

def filter_datum(
        fields: List[str], redaction: str, message: str, separator: str,
        ) -> str:
    """Filter log messages by obfuscating specified fields.
    
    Args:
        fields: List of field names to obfuscate.
        redaction: String to replace the field values with.
        message: The log message to be filtered.
        separator: The character separating fields in the log message.
    
    Returns:
        The obfuscated log message.
    """
    extract, replace = (patterns["extract"], patterns["replace"])
    return re.sub(extract(fields, separator), replace(redaction), message)

def get_logger() -> logging.Logger:
    """Create and configure a logger for user data.
    
    Returns:
        Configured logger object.
    """
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger

def get_db() -> mysql.connector.connection.MySQLConnection:
    """Establish a connection to the MySQL database.
    
    Returns:
        MySQL database connection object.
    """
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection

def main():
    """Retrieve and log user data from the database, obfuscating sensitive information.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)

class RedactingFormatter(logging.Formatter):
    """Formatter class to redact sensitive fields in log records.
    """

    REDACTION = "***"
    FORMAT = "[CUSTOM_LOG] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize the formatter with the fields to redact.
        
        Args:
            fields: List of field names to obfuscate in log messages.
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record, redacting sensitive fields.
        
        Args:
            record: The log record to be formatted.
        
        Returns:
            The formatted and obfuscated log message.
        """
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt

if __name__ == "__main__":
    main()
