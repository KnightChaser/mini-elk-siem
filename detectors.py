# detectors.py
import re
from typing import Union

# Precompile regex patterns for performance
XSS_PATTERNS = [
    (re.compile(r"<script.*?>.*?</script>", re.IGNORECASE | re.DOTALL), "Script Tag Injection"),
    (re.compile(r"on\w+\s*=\s*['\"].*?['\"]", re.IGNORECASE | re.DOTALL), "Event Handler Injection"),
    (re.compile(r"<.*?javascript:.*?>", re.IGNORECASE | re.DOTALL), "JavaScript URI Injection"),
    (re.compile(r"alert\s*\(", re.IGNORECASE), "Alert Function Injection"),
    (re.compile(r"on\w+\s*=\s*`.*?`", re.IGNORECASE | re.DOTALL), "Template Literal Event Handler Injection"),
    (re.compile(r"<img[^>]+src\s*=\s*['\"]\s*javascript:.*?['\"]", re.IGNORECASE | re.DOTALL), "Image Src JavaScript Injection"),
    (re.compile(r"<iframe.*?src\s*=\s*['\"].*?['\"]", re.IGNORECASE | re.DOTALL), "Iframe Injection"),
    (re.compile(r"eval\s*\(", re.IGNORECASE), "Eval Function Injection"),
    (re.compile(r"setTimeout\s*\(", re.IGNORECASE), "setTimeout Function Injection"),
    (re.compile(r"setInterval\s*\(", re.IGNORECASE), "setInterval Function Injection"),
    (re.compile(r"document\.cookie", re.IGNORECASE), "Cookie Access Injection"),
    (re.compile(r"window\.location", re.IGNORECASE), "Window Location Manipulation"),
    (re.compile(r"innerHTML\s*=", re.IGNORECASE), "DOM InnerHTML Injection"),
    (re.compile(r"document\.write\s*\(", re.IGNORECASE), "Document Write Injection"),
]

COMMAND_INJECTION_PATTERNS = [
    (re.compile(r";\s*[\w/]+", re.IGNORECASE), "Semicolon Command Injection"),
    (re.compile(r"&&\s*[\w/]+", re.IGNORECASE), "Logical AND Command Injection"),
    (re.compile(r"\|\|\s*[\w/]+", re.IGNORECASE), "Logical OR Command Injection"),
    (re.compile(r"\|\s*[\w/]+", re.IGNORECASE), "Pipe Command Injection"),
    (re.compile(r"`[^`]+`", re.IGNORECASE), "Backticks Command Injection"),
    (re.compile(r"\$\([^()]+\)", re.IGNORECASE), "Subshell Command Injection"),
    (re.compile(r"\b(wget|curl|nc|bash|perl|python|php)\b\s+", re.IGNORECASE), "Command Execution Injection"),
    (re.compile(r"\b(exec|system|shell_exec|popen|proc_open)\b\s*\(", re.IGNORECASE), "Function Call Injection"),
]

SQL_INJECTION_PATTERNS = [
    (re.compile(r"(['\"`])\s*;\s*--", re.IGNORECASE), "Comment Injection"),
    (re.compile(r"(['\"`])\s*OR\s+1=1\s*\1", re.IGNORECASE), "Logical OR Injection"),
    (re.compile(r"(['\"`])\s*AND\s+1=1\s*\1", re.IGNORECASE), "Logical AND Injection"),
    (re.compile(r"(UNION\s+SELECT)", re.IGNORECASE), "UNION Injection"),
    (re.compile(r"(DROP|DELETE|INSERT|UPDATE|SELECT)\s+\w+", re.IGNORECASE), "SQL Command Injection"),
    (re.compile(r"(['\"`])\s*(OR|AND)\s+\1\s*=\s*\1", re.IGNORECASE), "Empty String Comparison Injection"),
    (re.compile(r"(\bOR\b|\bAND\b)\s+\d+=\d+", re.IGNORECASE), "Numeric Comparison Injection"),
    (re.compile(r"--\s*$", re.IGNORECASE), "End-of-Line Comment Injection"),
    (re.compile(r";\s*(DROP|DELETE|INSERT|UPDATE|SELECT)\b", re.IGNORECASE), "Statement Termination Injection"),
    (re.compile(r"\bEXEC\b\s+\bXP_CMDSHELL\b", re.IGNORECASE), "Extended Stored Procedure Injection"),
    (re.compile(r"\bWAITFOR\b\s+DELAY\b", re.IGNORECASE), "Time Delay Injection"),
    (re.compile(r"\bDECLARE\b\s+", re.IGNORECASE), "Variable Declaration Injection"),
    (re.compile(r"(\bSELECT\b.*\bFROM\b.*\bWHERE\b)", re.IGNORECASE), "Standard SQL Injection"),
]

def detect_xss(request: str) -> Union[None, str]:
    """
    Detect potential XSS attacks in the request string.
    Returns the sub_attack_type if detected, otherwise None.
    """
    for pattern, sub_attack_type in XSS_PATTERNS:
        if pattern.search(request):
            return sub_attack_type
    return None

def detect_command_injection(request: str) -> Union[None, str]:
    """
    Detect potential command injection in the request string.
    Returns the sub_attack_type if detected, otherwise None.
    """
    for pattern, sub_attack_type in COMMAND_INJECTION_PATTERNS:
        if pattern.search(request):
            return sub_attack_type
    return None

def detect_sql_injection(request: str) -> Union[None, str]:
    """
    Detect potential SQL injection attacks in the request string.
    Returns the sub_attack_type if detected, otherwise None.
    """
    for pattern, sub_attack_type in SQL_INJECTION_PATTERNS:
        if pattern.search(request):
            return sub_attack_type
    return None

def detect_attack_type(request: str) -> Union[dict, None]:
    """
    Detect the type of suspicious attack based on the request string.
    Returns a dictionary with 'type' and 'sub_attack_type' if detected, otherwise None.
    """
    sub_attack_type = detect_xss(request)
    if sub_attack_type:
        return {"type": "XSS", "sub_attack_type": sub_attack_type}

    sub_attack_type = detect_command_injection(request)
    if sub_attack_type:
        return {"type": "Command Injection", "sub_attack_type": sub_attack_type}

    sub_attack_type = detect_sql_injection(request)
    if sub_attack_type:
        return {"type": "SQL Injection", "sub_attack_type": sub_attack_type}

    return None

