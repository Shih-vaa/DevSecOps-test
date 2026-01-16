#!/usr/bin/env python3
"""
Go Vulnerability Scanner
Detects common security vulnerabilities in Go code and generates JSON reports.
"""

import re
import json
import hashlib
import os
import sys
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple

class GoVulnerabilityDetector:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.project_name = os.path.basename(os.path.dirname(file_path))
        self.component_name = f"{self.project_name}:{os.path.relpath(file_path)}"
        self.vulnerabilities = []
        
        # Read file content
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.content = f.read()
        
        self.lines = self.content.split('\n')
        
    def generate_hash(self, text: str) -> str:
        """Generate MD5 hash for vulnerability identification"""
        return hashlib.md5(text.encode()).hexdigest()
    
    def create_vulnerability(self, rule: str, severity: str, line: int, message: str, 
                           vuln_type: str = "CODE_SMELL", effort: str = "5min",
                           tags: List[str] = None, flows: List[Dict] = None,
                           start_offset: int = 0, end_offset: int = None) -> Dict:
        """Create a vulnerability report in the specified format"""
        
        if tags is None:
            tags = ["security"]
        if flows is None:
            flows = []
        if end_offset is None:
            end_offset = len(self.lines[line - 1]) if line <= len(self.lines) else 0
        
        # Generate unique key
        key_text = f"{self.file_path}:{line}:{rule}:{message}"
        key = self.generate_hash(key_text)[:20]
        
        vuln = {
            "key": key,
            "rule": rule,
            "severity": severity,
            "component": self.component_name,
            "project": self.project_name,
            "line": line,
            "hash": self.generate_hash(f"{rule}:{line}:{message}"),
            "textRange": {
                "startLine": line,
                "endLine": line,
                "startOffset": start_offset,
                "endOffset": end_offset
            },
            "flows": flows,
            "status": "OPEN",
            "message": message,
            "effort": effort,
            "debt": effort,
            "author": "",
            "tags": tags,
            "creationDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0000"),
            "updateDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%S+0000"),
            "type": vuln_type,
            "scope": "MAIN",
            "quickFixAvailable": False,
            "messageFormattings": []
        }
        
        return vuln
    
    def detect_sql_injection(self):
        """Detect potential SQL injection vulnerabilities in Go code"""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER']
        
        # Patterns for dangerous SQL construction
        dangerous_patterns = [
            r'fmt\.Sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',  # fmt.Sprintf with SQL
            r'fmt\.Printf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',   # fmt.Printf with SQL
            r'"[^"]*(?:SELECT|INSERT|UPDATE|DELETE)[^"]*"\s*\+',       # String concatenation with SQL
            r'`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)[^`]*`\s*\+',       # Backtick string concatenation
            r'db\.Exec\s*\([^)]*fmt\.Sprintf',                         # db.Exec with fmt.Sprintf
            r'db\.Query\s*\([^)]*fmt\.Sprintf',                        # db.Query with fmt.Sprintf
            r'db\.QueryRow\s*\([^)]*fmt\.Sprintf',                     # db.QueryRow with fmt.Sprintf
            r'\.Exec\s*\([^)]*\+',                                     # Any .Exec with concatenation
            r'\.Query\s*\([^)]*\+',                                    # Any .Query with concatenation
        ]
        
        for i, line in enumerate(self.lines, 1):
            line_upper = line.upper()
            if any(keyword in line_upper for keyword in sql_keywords):
                # Check for dangerous patterns
                for pattern in dangerous_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = self.create_vulnerability(
                            rule="go:S2077",
                            severity="BLOCKER",
                            line=i,
                            message="Potential SQL injection vulnerability detected. Use parameterized queries with placeholders ($1, $2, etc.) instead of string concatenation or fmt.Sprintf.",
                            vuln_type="VULNERABILITY",
                            effort="30min",
                            tags=["security", "sql-injection"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
        
        # Check for missing parameterized queries in database operations
        db_operations = [
            r'db\.Exec\s*\([^$]*\)',
            r'db\.Query\s*\([^$]*\)',
            r'db\.QueryRow\s*\([^$]*\)',
            r'\.Exec\s*\([^$]*\)',
            r'\.Query\s*\([^$]*\)',
            r'\.QueryRow\s*\([^$]*\)'
        ]
        
        for i, line in enumerate(self.lines, 1):
            line_upper = line.upper()
            if any(keyword in line_upper for keyword in sql_keywords):
                for pattern in db_operations:
                    if re.search(pattern, line) and '$' not in line and '?' not in line:
                        # Check if this line contains user input variables
                        if re.search(r'\b(?:request|input|param|user|form|body|r\.URL|r\.FormValue)\b', line, re.IGNORECASE):
                            vuln = self.create_vulnerability(
                                rule="go:S2077",
                                severity="HIGH",
                                line=i,
                                message="SQL query contains user input without parameterization. Use $1, $2, etc. placeholders or ? placeholders depending on your database driver.",
                                vuln_type="VULNERABILITY",
                                effort="25min",
                                tags=["security", "sql-injection"]
                            )
                            self.vulnerabilities.append(vuln)
                            break
    
    def detect_hardcoded_secrets(self):
        """Detect hardcoded passwords, API keys, and secrets in Go code"""
        secret_patterns = [
            (r'(?i)password\s*[:=]\s*"[^"]{3,}"', "Hardcoded password detected"),
            (r'(?i)password\s*[:=]\s*`[^`]{3,}`', "Hardcoded password detected"),
            (r'(?i)apikey\s*[:=]\s*"[^"]{10,}"', "Hardcoded API key detected"),
            (r'(?i)api_key\s*[:=]\s*"[^"]{10,}"', "Hardcoded API key detected"),
            (r'(?i)secret\s*[:=]\s*"[^"]{10,}"', "Hardcoded secret detected"),
            (r'(?i)secretkey\s*[:=]\s*"[^"]{10,}"', "Hardcoded secret key detected"),
            (r'(?i)secret_key\s*[:=]\s*"[^"]{10,}"', "Hardcoded secret key detected"),
            (r'(?i)accesstoken\s*[:=]\s*"[^"]{10,}"', "Hardcoded access token detected"),
            (r'(?i)access_token\s*[:=]\s*"[^"]{10,}"', "Hardcoded access token detected"),
            (r'(?i)jwt[_-]?secret\s*[:=]\s*"[^"]{8,}"', "Hardcoded JWT secret detected"),
            (r'(?i)database[_-]?url\s*[:=]\s*"[^"]*://[^"]*:[^@"]+@[^"]*"', "Database URL with embedded credentials detected"),
            (r'(?i)conn[_-]?str\s*[:=]\s*"[^"]*password=[^;"]+[^"]*"', "Database connection string with password detected"),
            (r'const\s+\w*(?:password|secret|key|token)\w*\s*=\s*"[^"]{8,}"', "Hardcoded secret in const declaration"),
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern, message in secret_patterns:
                if re.search(pattern, line):
                    vuln = self.create_vulnerability(
                        rule="go:S2068",
                        severity="BLOCKER",
                        line=i,
                        message=message + ". Use environment variables (os.Getenv) or secure configuration management instead.",
                        vuln_type="VULNERABILITY",
                        effort="15min",
                        tags=["security", "credentials"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def detect_broken_access_control(self):
        """Detect potential broken access control issues in Go code"""
        # Look for HTTP handlers that might need authorization
        handler_patterns = [
            r'func\s+(\w*(?:admin|delete|create|update|manage|grant|revoke)\w*)\s*\([^)]*http\.ResponseWriter',
            r'func\s+(\w*(?:Admin|Delete|Create|Update|Manage|Grant|Revoke)\w*)\s*\([^)]*http\.ResponseWriter',
            r'\.(?:POST|PUT|DELETE|PATCH)\s*\([^)]*,\s*(\w*(?:admin|delete|create|update|manage)\w*)',
        ]
        
        auth_patterns = [
            r'(?i)middleware\.auth',
            r'(?i)authenticate',
            r'(?i)authorize',
            r'(?i)checkpermission',
            r'(?i)requireauth',
            r'(?i)requireadmin',
            r'(?i)jwt\.parse',
            r'(?i)token\.valid',
            r'(?i)session\.get',
            r'(?i)user\.role',
            r'(?i)admin.*check',
            r'if.*role.*==.*admin',
            r'if.*permission',
            r'if.*authorized',
        ]
        
        for i, line in enumerate(self.lines, 1):
            # Check for privileged function handlers
            for pattern in handler_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    function_name = match.group(1) if match.groups() else "unknown"
                    
                    # Look for auth checks in the next 20 lines
                    has_auth_check = False
                    for j in range(max(0, i-5), min(len(self.lines), i+20)):
                        check_line = self.lines[j]
                        if any(re.search(auth_pattern, check_line) for auth_pattern in auth_patterns):
                            has_auth_check = True
                            break
                    
                    if not has_auth_check:
                        vuln = self.create_vulnerability(
                            rule="go:S5144",
                            severity="HIGH",
                            line=i,
                            message=f"Potential broken access control: Handler '{function_name}' appears to be privileged but lacks proper authorization checks.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "access-control"]
                        )
                        self.vulnerabilities.append(vuln)
    
    def detect_xss_vulnerabilities(self):
        """Detect potential XSS vulnerabilities in Go code"""
        # Existing heuristics for dangerous patterns
        dangerous_output_patterns = [
            r'template\.HTML\s*\(',                      # template.HTML without sanitization
            r'\bw\.Write\s*\([^)]*\+',                   # Direct write with concatenation
            r'fmt\.Fprint[f]?\s*\([^)]*\+',              # fmt.Fprint/Fprintf with concatenation
            r'fmt\.Fprint[f]?\s*\([^,]*,\s*[^,]+\)',     # fmt.Fprint where second arg could be user input
            r'\.WriteString\s*\([^)]*\+',                # WriteString with concatenation
        ]
        
        # User input sources / patterns
        user_input_patterns = [
            r'\br\.FormValue\b',
            r'\br\.PostFormValue\b',
            r'\br\.URL\.Query\b',
            r'\br\.Form\b',
            r'\brequest\.',
            r'\bform\.',
            r'\bquery\.',
            r'\bparam\.',
            r'\binput\.',
            r'mux\.Vars',
            r'\bc\.Query\b',    # gin
            r'\bc\.Param\b',    # gin/echo
            r'\bc\.FormValue\b',
            r'\bc\.QueryParam\b',
        ]
        
        # First: flag obvious dangerous writes / fmt usage
        for i, line in enumerate(self.lines, 1):
            for pattern in dangerous_output_patterns:
                if re.search(pattern, line):
                    # If concatenation or fmt.Sprintf/fprint with user input is used, flag it
                    has_user_input = any(re.search(p, line) for p in user_input_patterns)
                    uses_concat = '+' in line or re.search(r'fmt\.Sprintf\s*\(', line)
                    
                    if has_user_input or uses_concat:
                        vuln = self.create_vulnerability(
                            rule="go:S5131",
                            severity="HIGH",
                            line=i,
                            message="Potential XSS: user-controlled data is written to the response without proper escaping. Use html/template, html.EscapeString(), or proper escaping/sanitization.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "xss"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
        
        # Detect usage of text/template for web output instead of html/template
        imports_block = '\n'.join(self.lines)
        imported_text_template = bool(re.search(r'import\s*\([^\)]*["\']text/template["\']|import\s+["\']text/template["\']', imports_block))
        imported_html_template = bool(re.search(r'import\s*\([^\)]*["\']html/template["\']|import\s+["\']html/template["\']', imports_block))
        
        if imported_text_template and not imported_html_template:
            # find line numbers where text/template is imported for better reporting
            for i, line in enumerate(self.lines, 1):
                if 'text/template' in line:
                    vuln = self.create_vulnerability(
                        rule="go:S5131",
                        severity="MEDIUM",
                        line=i,
                        message="Using text/template for web output can lead to XSS because it does not auto-escape HTML. Use html/template for web templates.",
                        vuln_type="VULNERABILITY",
                        effort="15min",
                        tags=["security", "xss", "template"]
                    )
                    self.vulnerabilities.append(vuln)
                    break
        
        # Detect direct use of template.HTML which bypasses escaping
        for i, line in enumerate(self.lines, 1):
            if 'template.HTML' in line:
                vuln = self.create_vulnerability(
                    rule="go:S5131",
                    severity="HIGH",
                    line=i,
                    message="Direct use of template.HTML detected: this bypasses automatic escaping and can introduce XSS. Avoid using template.HTML with untrusted input.",
                    vuln_type="VULNERABILITY",
                    effort="20min",
                    tags=["security", "xss"]
                )
                self.vulnerabilities.append(vuln)

        # New heuristic: track variables assigned from user-controlled sources and detect when they are later passed to templates / response writers
        user_var_assign_re = re.compile(
            r'\b(?P<var>\w+)\s*(?:[:=]{1,2})\s*.*\b(r\.URL\.Query\.Get|r\.FormValue|r\.PostFormValue|r\.Form|r\.Body|request\.|r\.URL\.Query|r\.Query|mux\.Vars|c\.Param|c\.Query)\b',
            re.IGNORECASE
        )
        user_vars = {}  # var_name -> line_num
        for i, line in enumerate(self.lines, 1):
            m = user_var_assign_re.search(line)
            if m:
                var = m.group('var')
                user_vars[var] = i
        
        # Look for template.Execute, fmt.Fprintf, FprintF, w.Write that reference user-controlled vars
        sink_patterns = [r'\.Execute\s*\(', r'fmt\.Fprintf\s*\(', r'fmt\.Fprint\s*\(', r'w\.Write\s*\(', r'http\.Redirect\s*\(']
        for i, line in enumerate(self.lines, 1):
            if any(re.search(p, line) for p in sink_patterns):
                # look around the sink for use of user vars
                context = '\n'.join(self.lines[max(0, i-3):min(len(self.lines), i+3)])
                for var, assign_line in user_vars.items():
                    # only consider vars assigned earlier than sink
                    if assign_line <= i and re.search(r'\b' + re.escape(var) + r'\b', context):
                        vuln = self.create_vulnerability(
                            rule="go:S5131",
                            severity="HIGH",
                            line=i,
                            message=f"Possible XSS: user-controlled variable '{var}' (from request) is written to a template/response without explicit escaping or validation.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "xss"]
                        )
                        self.vulnerabilities.append(vuln)
                        # once flagged for this sink, don't duplicate for other vars in same sink
                        break
    
    def detect_insecure_deserialization(self):
        """Detect insecure deserialization vulnerabilities in Go code"""
        dangerous_patterns = [
            r'gob\.Decode\s*\(',  # gob deserialization
            r'json\.Unmarshal\s*\([^)]*,\s*&\w+\)',  # JSON unmarshaling into interface{}
            r'yaml\.Unmarshal\s*\(',  # YAML unmarshaling
            r'xml\.Unmarshal\s*\(',  # XML unmarshaling
            r'binary\.Read\s*\(',  # Binary deserialization
        ]
        
        user_input_sources = [
            r'r\.Body',
            r'request\.',
            r'c\.Request',
            r'c\.Body',
            r'form\.',
            r'query\.',
            r'param\.',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line):
                    # Check if deserializing user input
                    context_lines = self.lines[max(0, i-3):min(len(self.lines), i+3)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_sources)
                    
                    if has_user_input:
                        vuln = self.create_vulnerability(
                            rule="go:S5144",
                            severity="HIGH",
                            line=i,
                            message="Potential insecure deserialization: Deserializing user input without validation. Validate input structure and consider using safer formats.",
                            vuln_type="VULNERABILITY",
                            effort="30min",
                            tags=["security", "deserialization"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
        
        # Check for interface{} deserialization which can be dangerous
        interface_patterns = [
            r'json\.Unmarshal\s*\([^)]*,\s*&?interface\{\}\)',
            r'yaml\.Unmarshal\s*\([^)]*,\s*&?interface\{\}\)',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in interface_patterns:
                if re.search(pattern, line):
                    vuln = self.create_vulnerability(
                        rule="go:S5144",
                        severity="MEDIUM",
                        line=i,
                        message="Deserialization into interface{}: This can be dangerous as it allows arbitrary types. Use specific struct types instead.",
                        vuln_type="VULNERABILITY",
                        effort="20min",
                        tags=["security", "deserialization"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def detect_unused_imports_variables(self):
        """Detect unused imports and variables in Go code (made more generic)"""
        # Improved import parsing to correctly handle import blocks and single imports,
        # and a more reliable heuristic for standard library vs external packages.
        import_block = False
        imported_packages = {}  # package_name -> (line_num, package_path, alias)
        
        for i, line in enumerate(self.lines, 1):
            stripped = line.strip()
            
            # Start of import block
            if stripped.startswith('import ('):
                import_block = True
                continue
            if import_block and stripped == ')':
                import_block = False
                continue
            
            # Inside import block
            if import_block:
                # Skip comments and blank lines
                if not stripped or stripped.startswith('//'):
                    continue
                m = re.search(r'(?:(?P<alias>\w+|\.)\s+)?["`](?P<pkg>[^"`]+)["`]', line)
                if m:
                    alias = m.group('alias') if m.group('alias') else None
                    pkg_path = m.group('pkg')
                    if alias and alias not in ['.']:
                        pkg_name = alias
                    else:
                        pkg_name = pkg_path.split('/')[-1]
                    imported_packages[pkg_name] = (i, pkg_path, alias)
                continue
            
            # Single-line import
            if stripped.startswith('import '):
                m = re.search(r'import\s+(?:(?P<alias>\w+|\.)\s+)?["\'](?P<pkg>[^"\']+)["\']', line)
                if m:
                    alias = m.group('alias') if m.group('alias') else None
                    pkg_path = m.group('pkg')
                    pkg_name = alias if alias and alias not in ['.'] else pkg_path.split('/')[-1]
                    imported_packages[pkg_name] = (i, pkg_path, alias)
        
        # Remove import blocks and single imports from content to reduce false positives
        content_no_imports = re.sub(r'import\s*\([\s\S]*?\)', '', self.content, flags=re.M)
        content_no_imports = re.sub(r'import\s+["\'][^"\']+["\']', '', content_no_imports)
        
        for pkg_name, (line_num, pkg_path, alias) in imported_packages.items():
            # Keep dot imports out of automated checks (hard to analyze)
            if alias == '.':
                continue
            
            # Determine usage heuristics:
            # - If alias is '_' or a name, check if package name or basename appears in code
            # - Do not ignore stdlib packages: unused stdlib imports are valid to flag
            usage_patterns = []
            if alias and alias != '_':
                usage_patterns.append(rf'\b{re.escape(alias)}\.')   # alias.Func()
                usage_patterns.append(rf'\b{re.escape(alias)}\s*\(') # alias() calls
            else:
                # If alias is '_' or None, use package base name heuristics
                base_name = pkg_path.split('/')[-1]
                usage_patterns.append(rf'\b{re.escape(base_name)}\.')
                usage_patterns.append(rf'\b{re.escape(base_name)}\s*\(')
            
            is_used = any(re.search(p, content_no_imports) for p in usage_patterns)
            
            # Also check full import path (last segment) in case package name differs
            if not is_used:
                basename = pkg_path.split('/')[-1]
                if basename != pkg_name:
                    is_used = bool(re.search(rf'\b{re.escape(basename)}\.', content_no_imports))
            
            # Special handling: underscore imports are intended for side-effects. If the package path
            # does not look like a common side-effect initializer (very hard to know), still flag as unused
            # to match user's request for detecting unused imports.
            if not is_used:
                vuln = self.create_vulnerability(
                    rule="go:F401",
                    severity="MINOR",
                    line=line_num,
                    message=f"Unused import '{pkg_name}' ({pkg_path}). Remove unused imports to improve code quality and reduce build size.",
                    vuln_type="CODE_SMELL",
                    effort="2min",
                    tags=["code-quality", "unused-code"]
                )
                self.vulnerabilities.append(vuln)
    
    def detect_invalid_redirects(self):
        """Detect invalid redirects and forwards in Go code"""
        redirect_patterns = [
            r'http\.Redirect\s*\([^)]*,\s*([^,)]+)',
            r'c\.Redirect\s*\([^)]*,\s*([^,)]+)',  # Gin, Echo
            r'\.Redirect\s*\([^)]*,\s*([^,)]+)',
        ]
        
        user_input_patterns = [
            r'r\.URL\.Query',
            r'r\.FormValue',
            r'r\.PostFormValue',
            r'mux\.Vars',
            r'c\.Query',
            r'c\.Param',
            r'c\.FormValue',
            r'c\.QueryParam',
            r'request\.',
            r'form\.',
            r'query\.',
            r'param\.',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in redirect_patterns:
                match = re.search(pattern, line)
                if match:
                    redirect_target = match.group(1).strip()
                    
                    # Check if redirect URL comes from user input
                    context_lines = self.lines[max(0, i-5):min(len(self.lines), i+5)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_patterns)
                    
                    # Also check if the redirect target itself looks like user input
                    is_user_controlled = any(input_type in redirect_target.lower() for input_type in ['query', 'form', 'param', 'request', 'input'])
                    
                    if has_user_input or is_user_controlled:
                        vuln = self.create_vulnerability(
                            rule="go:S5146",
                            severity="MEDIUM",
                            line=i,
                            message="Potential unvalidated redirect: Redirect URL comes from user input. Validate and whitelist redirect URLs to prevent phishing attacks.",
                            vuln_type="VULNERABILITY",
                            effort="15min",
                            tags=["security", "redirect"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
    
    def detect_insufficient_logging(self):
        """Detect insufficient logging and monitoring in Go code"""
        # Check for logging imports
        has_logging_import = any(
            re.search(r'import.*"(?:log|logrus|zap|zerolog)"', line) or
            re.search(r'"(?:log|logrus|zap|zerolog|github\.com/sirupsen/logrus)"', line)
            for line in self.lines
        )
        
        security_events = ['login', 'logout', 'auth', 'permission', 'admin', 'access', 'session']
        logging_functions = ['log\.', 'logger\.', 'Log', 'Info', 'Error', 'Warn', 'Debug']
        
        # Find security-related functions
        for i, line in enumerate(self.lines, 1):
            # Look for function definitions that handle security events
            func_match = re.search(r'func\s+(\w*(?:' + '|'.join(security_events) + r')\w*)\s*\(', line, re.IGNORECASE)
            if func_match:
                function_name = func_match.group(1)
                
                # Check if function contains logging calls in next 20 lines
                has_log_call = False
                for j in range(i, min(len(self.lines), i+20)):
                    check_line = self.lines[j]
                    if any(re.search(log_func, check_line) for log_func in logging_functions):
                        has_log_call = True
                        break
                    # Break if we hit another function
                    if j > i and re.search(r'^func\s+\w+', check_line):
                        break
                
                if not has_log_call:
                    vuln = self.create_vulnerability(
                        rule="go:S2629",
                        severity="MEDIUM",
                        line=i,
                        message=f"Insufficient logging: Security-related function '{function_name}' lacks proper logging. Add logging for security events to enable monitoring and incident response.",
                        vuln_type="CODE_SMELL",
                        effort="10min",
                        tags=["security", "logging"]
                    )
                    self.vulnerabilities.append(vuln)
        
        # Check for error handling without logging
        error_patterns = [
            r'if\s+err\s*!=\s*nil\s*{[^}]*return[^}]*}',  # Error return without logging
            r'if\s+.*error.*{[^}]*return[^}]*}',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in error_patterns:
                if re.search(pattern, line):
                    # Check if there's logging in the error handling block
                    context_lines = self.lines[i-1:min(len(self.lines), i+5)]
                    context = ' '.join(context_lines)
                    
                    has_logging = any(re.search(log_func, context) for log_func in logging_functions)
                    
                    if not has_logging and 'log' not in context.lower():
                        vuln = self.create_vulnerability(
                            rule="go:S2629",
                            severity="LOW",
                            line=i,
                            message="Error handling without logging: Errors should be logged for debugging and monitoring purposes.",
                            vuln_type="CODE_SMELL",
                            effort="5min",
                            tags=["logging", "error-handling"]
                        )
                        self.vulnerabilities.append(vuln)
    
    def detect_vulnerable_dependencies(self):
        """Detect vulnerable and outdated components in Go modules"""
        # Check for go.mod file
        project_dir = os.path.dirname(self.file_path)
        go_mod_path = os.path.join(project_dir, 'go.mod')
        go_sum_path = os.path.join(project_dir, 'go.sum')
        
        # Common packages with known vulnerabilities (simplified check)
        known_vulnerabilities = {
            'github.com/gorilla/websocket': 'v1.4.1',
            'github.com/gin-gonic/gin': 'v1.7.0',
            'github.com/labstack/echo': 'v4.6.0',
            'gopkg.in/yaml.v2': 'v2.4.0',
            'github.com/dgrijalva/jwt-go': 'v3.2.0',  # Deprecated, should use golang-jwt
        }
        
        deprecated_packages = [
            'github.com/dgrijalva/jwt-go',  # Use github.com/golang-jwt/jwt instead
            'golang.org/x/crypto/ssh/terminal',  # Use golang.org/x/term
        ]
        
        if os.path.exists(go_mod_path):
            try:
                with open(go_mod_path, 'r') as f:
                    content = f.read()
                
                for package, min_version in known_vulnerabilities.items():
                    if package in content:
                        vuln = self.create_vulnerability(
                            rule="go:S4830",
                            severity="HIGH",
                            line=1,
                            message=f"Potentially vulnerable dependency detected: '{package}'. Ensure you're using version >= {min_version} or the latest secure version.",
                            vuln_type="VULNERABILITY",
                            effort="10min",
                            tags=["security", "dependencies"]
                        )
                        self.vulnerabilities.append(vuln)
                
                for deprecated_pkg in deprecated_packages:
                    if deprecated_pkg in content:
                        vuln = self.create_vulnerability(
                            rule="go:S4830",
                            severity="MEDIUM",
                            line=1,
                            message=f"Deprecated package detected: '{deprecated_pkg}'. Update to the recommended alternative.",
                            vuln_type="CODE_SMELL",
                            effort="15min",
                            tags=["security", "deprecated"]
                        )
                        self.vulnerabilities.append(vuln)
                        
            except Exception:
                pass
        
        # Check for CGO usage which can introduce vulnerabilities
        cgo_patterns = [
            r'import\s+"C"',
            r'#include\s+<',
            r'//\s*#cgo\s+',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in cgo_patterns:
                if re.search(pattern, line):
                    vuln = self.create_vulnerability(
                        rule="go:S4830",
                        severity="MEDIUM",
                        line=i,
                        message="CGO usage detected: CGO can introduce memory safety vulnerabilities. Ensure C code is secure and consider pure Go alternatives.",
                        vuln_type="CODE_SMELL",
                        effort="20min",
                        tags=["security", "cgo"]
                    )
                    self.vulnerabilities.append(vuln)
                    break
    
    def run_all_detections(self):
        """Run all vulnerability detections"""
        self.detect_sql_injection()
        self.detect_hardcoded_secrets()
        self.detect_broken_access_control()
        self.detect_xss_vulnerabilities()
        self.detect_insecure_deserialization()
        self.detect_unused_imports_variables()
        self.detect_invalid_redirects()
        self.detect_insufficient_logging()
        self.detect_vulnerable_dependencies()
        
        return self.vulnerabilities

def scan_file(file_path: str) -> List[Dict]:
    """Scan a single Go file for vulnerabilities"""
    detector = GoVulnerabilityDetector(file_path)
    return detector.run_all_detections()

def scan_directory(directory: str) -> List[Dict]:
    """Scan all Go files in a directory"""
    all_vulnerabilities = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.go'):
                file_path = os.path.join(root, file)
                try:
                    vulnerabilities = scan_file(file_path)
                    all_vulnerabilities.extend(vulnerabilities)
                except Exception as e:
                    print(f"Error scanning {file_path}: {e}")
    
    return all_vulnerabilities

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python go_vuln_scanner.py <file_or_directory> [output_file.json]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "go_vulnerabilities.json"
    
    vulnerabilities = []
    
    if os.path.isfile(target) and target.endswith('.go'):
        vulnerabilities = scan_file(target)
    elif os.path.isdir(target):
        vulnerabilities = scan_directory(target)
    else:
        print(f"Error: {target} is not a valid Go file or directory")
        sys.exit(1)
    
    # Save results to JSON file
    with open(output_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
    
    print(f"Go vulnerability scan completed. Found {len(vulnerabilities)} potential vulnerabilities.")
    print(f"Results saved to {output_file}")
    
    # Print summary
    if vulnerabilities:
        severity_counts = {}
        type_counts = {}
        rule_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln['severity']
            vuln_type = vuln['type']
            rule = vuln['rule']
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        print("\n=== VULNERABILITY SUMMARY ===")
        print("\nBy Severity:")
        for severity in ["BLOCKER", "HIGH", "MEDIUM", "LOW", "MINOR"]:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]}")
        
        print("\nBy Type:")
        for vuln_type, count in sorted(type_counts.items()):
            print(f"  {vuln_type}: {count}")
        
        print("\nTop Vulnerability Rules:")
        for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {rule}: {count}")
        
        print("\n=== DETAILED FINDINGS ===")
        current_file = None
        for vuln in sorted(vulnerabilities, key=lambda x: (x['component'], x['line'])):
            if current_file != vuln['component']:
                current_file = vuln['component']
                print(f"\n📁 {current_file}")
            
            severity_emoji = {
                "BLOCKER": "🔴",
                "HIGH": "🟠", 
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "MINOR": "⚪"
            }.get(vuln['severity'], "❓")
            
            print(f"  {severity_emoji} Line {vuln['line']}: {vuln['message'][:100]}{'...' if len(vuln['message']) > 100 else ''}")
    else:
        print("\n✅ No vulnerabilities found! Your Go code looks secure.")

if __name__ == "__main__":
    main()