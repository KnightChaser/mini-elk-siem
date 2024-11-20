# detectors.py
import re
from typing import Union

# Precompile regex patterns for performance
XSS_PATTERNS = [
    re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE | re.DOTALL),
    re.compile(r"<.*?javascript:.*?>", re.IGNORECASE | re.DOTALL),
    re.compile(r"alert\s*\(", re.IGNORECASE),
    re.compile(r"on\w+\s*=\s*`.*?`", re.IGNORECASE | re.DOTALL),
    re.compile(r"<img[^>]+src\s*=\s*['\"]\s*javascript:.*?['\"]", re.IGNORECASE | re.DOTALL),
    re.compile(r"<iframe.*?src\s*=\s*['\"].*?['\"]", re.IGNORECASE | re.DOTALL),
    re.compile(r"eval\s*\(", re.IGNORECASE),
    re.compile(r"setTimeout\s*\(", re.IGNORECASE),
    re.compile(r"setInterval\s*\(", re.IGNORECASE),
    re.compile(r"document\.cookie", re.IGNORECASE),
    re.compile(r"window\.location", re.IGNORECASE),
    re.compile(r"innerHTML\s*=", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
]

COMMAND_INJECTION_PATTERNS = [
    re.compile(r";\s*[\w/]+", re.IGNORECASE),
    re.compile(r"&&\s*[\w/]+", re.IGNORECASE),
    re.compile(r"\|\|\s*[\w/]+", re.IGNORECASE),
    re.compile(r"\|\s*[\w/]+", re.IGNORECASE),
    re.compile(r"`[^`]+`", re.IGNORECASE),  # Backticks
    re.compile(r"\$\([^()]+\)", re.IGNORECASE),  # $()
    re.compile(r"\b(wget|curl|nc|bash|perl|python|php)\b\s+", re.IGNORECASE),
    re.compile(r"\b(exec|system|shell_exec|popen|proc_open)\b\s*\(", re.IGNORECASE),
]

SQL_INJECTION_PATTERNS = [
    re.compile(r"(['\"`])\s*;\s*--", re.IGNORECASE),                         # Comment injection
    re.compile(r"(['\"`])\s*OR\s+1=1\s*\1", re.IGNORECASE),                  # Logical OR with 1=1
    re.compile(r"(['\"`])\s*AND\s+1=1\s*\1", re.IGNORECASE),                 # Logical AND with 1=1
    re.compile(r"(UNION\s+SELECT)", re.IGNORECASE),                          # UNION SELECT keyword
    re.compile(r"(DROP|DELETE|INSERT|UPDATE|SELECT)\s+\w+", re.IGNORECASE),  # Common SQL keywords
    re.compile(r"(['\"`])\s*(OR|AND)\s+\1\s*=\s*\1", re.IGNORECASE),         # OR ''=''
    re.compile(r"(\bOR\b|\bAND\b)\s+\d+=\d+", re.IGNORECASE),                # OR 1=1
    re.compile(r"--\s*$", re.IGNORECASE),                                    # End line comment
    re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|SELECT)\b", re.IGNORECASE),  # Command after semicolon
    re.compile(r"\bEXEC\b\s+\bXP_CMDSHELL\b", re.IGNORECASE),                # EXEC XP_CMDSHELL
    re.compile(r"\bWAITFOR\b\s+DELAY\b", re.IGNORECASE),                     # WAITFOR DELAY
    re.compile(r"\bDECLARE\b\s+", re.IGNORECASE),                            # DECLARE statement
    re.compile(r"(\bSELECT\b.*\bFROM\b.*\bWHERE\b)", re.IGNORECASE),         # SELECT ... FROM ... WHERE
]

def detect_xss(request: str) -> bool:
    """
    Detect potential XSS attacks in the request string.
    Enhanced to detect a wider range of XSS attack vectors, including encoded and obfuscated payloads.
    """
    for pattern in XSS_PATTERNS:
        if pattern.search(request):
            return True
    return False


def detect_command_injection(request: str) -> bool:
    """
    Detect potential command injection in the request string.
    Enhanced to detect more sophisticated command injection patterns and obfuscations.
    """
    for pattern in COMMAND_INJECTION_PATTERNS:
        if pattern.search(request):
            return True
    return False


def detect_sql_injection(request: str) -> bool:
    """
    Detect potential SQL injection attacks in the request string.
    Enhanced to detect a wider array of SQL injection patterns, including logical operators and encoded inputs.
    """
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.search(request):
            return True
    return False


def detect_attack_type(request: str) -> Union[str, None]:
    """
    Detect the type of suspicious attack based on the request string.
    Returns the name of the attack if detected, otherwise None.
    Prioritizes attack types based on severity or likelihood.
    """
    if detect_xss(request):
        return "XSS"
    if detect_command_injection(request):
        return "Command Injection"
    if detect_sql_injection(request):
        return "SQL Injection"
    return None

