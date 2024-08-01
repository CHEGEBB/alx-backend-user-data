#!/usr/bin/env python3
"""
Filtered Logger
"""

import re
from typing import List

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """
    Return the log message obfuscated.
    """
    return re.sub(
        fr'({"|".join(fields)})=[^ {separator}]*',
        fr'\1={redaction}',
        message
    )
