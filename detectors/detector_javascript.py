#!/usr/bin/env python3
"""
JavaScript Vulnerability Scanner
Detects common security vulnerabilities in JavaScript code and generates JSON reports.
Supports vanilla JS, Node.js, React, Vue, Angular, Express.js, and other frameworks.
"""

import re
import json
import hashlib
import os
import sys
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple

class JSVulnerabilityDetector:
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
        """Detect potential SQL injection vulnerabilities in JavaScript code"""
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER', 'UNION', 'WHERE']
        
        # Patterns for dangerous SQL construction in JavaScript
        dangerous_patterns = [
            r'["`\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\+',  # String concatenation with SQL
            r'["`\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?\$\{',  # Template literals with variables
            r'query\s*\(\s*["`\'].*?\+',  # Query function with concatenation
            r'\.query\s*\([^)]*\+',  # Any .query() with concatenation
            r'\.execute\s*\([^)]*\+',  # Any .execute() with concatenation
            r'sql\s*\+\s*',  # SQL variable concatenation
            r'["`\'].*?(?:SELECT|INSERT|UPDATE|DELETE).*?["`\']\s*\+\s*\w+',  # Direct SQL + variable
            r'String\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',  # String.format with SQL
            r'sprintf\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',  # sprintf with SQL
            r'util\.format\s*\([^)]*(?:SELECT|INSERT|UPDATE|DELETE)',  # util.format with SQL
        ]
        
        # Database operation patterns (various libraries)
        db_operation_patterns = [
            r'db\.query\s*\(',  # Generic db.query
            r'connection\.query\s*\(',  # MySQL connection.query
            r'client\.query\s*\(',  # PostgreSQL client.query
            r'pool\.query\s*\(',  # Connection pool query
            r'sequelize\.query\s*\(',  # Sequelize raw query
            r'knex\.raw\s*\(',  # Knex raw query
            r'\.execute\s*\(',  # Execute method
            r'\.run\s*\(',  # SQLite run method
            r'collection\.find\s*\(',  # MongoDB find (NoSQL injection)
            r'collection\.findOne\s*\(',  # MongoDB findOne
            r'Model\.find\s*\(',  # Mongoose/ORM find
            r'\.aggregate\s*\(',  # MongoDB aggregate
        ]
        
        for i, line in enumerate(self.lines, 1):
            line_upper = line.upper()
            if any(keyword in line_upper for keyword in sql_keywords):
                # Check for dangerous patterns
                for pattern in dangerous_patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vuln = self.create_vulnerability(
                            rule="js:S2077",
                            severity="BLOCKER",
                            line=i,
                            message="Potential SQL injection vulnerability detected. Use parameterized queries or prepared statements instead of string concatenation.",
                            vuln_type="VULNERABILITY",
                            effort="30min",
                            tags=["security", "sql-injection"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
        
        # Check for unsafe database operations
        user_input_sources = [
            r'req\.body',
            r'req\.query',
            r'req\.params',
            r'req\.headers',
            r'request\.body',
            r'request\.query',
            r'ctx\.request',
            r'ctx\.query',
            r'this\.\$route\.query',
            r'this\.\$route\.params',
            r'props\.',
            r'state\.',
            r'useState',
            r'useParams',
            r'useQuery',
            r'location\.search',
            r'window\.location',
            r'document\.cookie',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for db_pattern in db_operation_patterns:
                if re.search(db_pattern, line):
                    # Check if user input is used in the query
                    context_lines = self.lines[max(0, i-3):min(len(self.lines), i+3)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_sources)
                    has_concatenation = '+' in line or '${' in line or '`' in line
                    
                    if has_user_input and has_concatenation:
                        vuln = self.create_vulnerability(
                            rule="js:S2077",
                            severity="HIGH",
                            line=i,
                            message="Database query contains user input without proper sanitization. Use parameterized queries or ORM methods to prevent injection attacks.",
                            vuln_type="VULNERABILITY",
                            effort="25min",
                            tags=["security", "sql-injection"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
    
    def detect_hardcoded_secrets(self):
        """Detect hardcoded passwords, API keys, and secrets in JavaScript code"""
        secret_patterns = [
            (r'(?i)password\s*[:=]\s*["`\'][^"`\']{3,}["`\']', "Hardcoded password detected"),
            (r'(?i)passwd\s*[:=]\s*["`\'][^"`\']{3,}["`\']', "Hardcoded password detected"),
            (r'(?i)pwd\s*[:=]\s*["`\'][^"`\']{3,}["`\']', "Hardcoded password detected"),
            (r'(?i)api[_-]?key\s*[:=]\s*["`\'][^"`\']{10,}["`\']', "Hardcoded API key detected"),
            (r'(?i)apikey\s*[:=]\s*["`\'][^"`\']{10,}["`\']', "Hardcoded API key detected"),
            (r'(?i)secret[_-]?key\s*[:=]\s*["`\'][^"`\']{10,}["`\']', "Hardcoded secret key detected"),
            (r'(?i)secretkey\s*[:=]\s*["`\'][^"`\']{10,}["`\']', "Hardcoded secret key detected"),
            (r'(?i)access[_-]?token\s*[:=]\s*["`\'][^"`\']{10,}["`\']', "Hardcoded access token detected"),
            (r'(?i)accesstoken\s*[:=]\s*["`\'][^"`\']{10,}["`\']', "Hardcoded access token detected"),
            (r'(?i)jwt[_-]?secret\s*[:=]\s*["`\'][^"`\']{8,}["`\']', "Hardcoded JWT secret detected"),
            (r'(?i)database[_-]?url\s*[:=]\s*["`\'].*://.*:[^@"`\']+@.*["`\']', "Database URL with embedded credentials detected"),
            (r'(?i)db[_-]?url\s*[:=]\s*["`\'].*://.*:[^@"`\']+@.*["`\']', "Database URL with embedded credentials detected"),
            (r'(?i)connection[_-]?string\s*[:=]\s*["`\'].*password=.*["`\']', "Database connection string with password detected"),
            (r'(?i)private[_-]?key\s*[:=]\s*["`\'][^"`\']{20,}["`\']', "Hardcoded private key detected"),
            (r'(?i)aws[_-]?access[_-]?key\s*[:=]\s*["`\'][^"`\']{16,}["`\']', "Hardcoded AWS access key detected"),
            (r'(?i)aws[_-]?secret[_-]?key\s*[:=]\s*["`\'][^"`\']{20,}["`\']', "Hardcoded AWS secret key detected"),
            (r'const\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|API)\w*\s*=\s*["`\'][^"`\']{8,}["`\']', "Hardcoded secret in const declaration"),
            (r'let\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|API)\w*\s*=\s*["`\'][^"`\']{8,}["`\']', "Hardcoded secret in let declaration"),
            (r'var\s+\w*(?:PASSWORD|SECRET|KEY|TOKEN|API)\w*\s*=\s*["`\'][^"`\']{8,}["`\']', "Hardcoded secret in var declaration"),
            (r'process\.env\.\w*\s*\|\|\s*["`\'][^"`\']{8,}["`\']', "Hardcoded fallback secret for environment variable"),
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern, message in secret_patterns:
                if re.search(pattern, line):
                    # Skip if it's obviously a placeholder or example
                    if any(placeholder in line.lower() for placeholder in ['example', 'placeholder', 'your_key', 'your_password', 'xxx', '***', '...', 'todo']):
                        continue
                    
                    vuln = self.create_vulnerability(
                        rule="js:S2068",
                        severity="BLOCKER",
                        line=i,
                        message=message + ". Use environment variables (process.env) or secure configuration management instead.",
                        vuln_type="VULNERABILITY",
                        effort="15min",
                        tags=["security", "credentials"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def detect_broken_access_control(self):
        """Detect potential broken access control issues in JavaScript code"""
        # Look for routes/endpoints that might need authorization
        route_patterns = [
            r'\.(?:get|post|put|delete|patch)\s*\(["`\'][^"`\']*(?:admin|delete|create|update|manage|grant|revoke)',  # Express routes
            r'app\.(?:get|post|put|delete|patch)\s*\(["`\'][^"`\']*(?:admin|delete|create|update|manage)',  # Express app routes
            r'router\.(?:get|post|put|delete|patch)\s*\(["`\'][^"`\']*(?:admin|delete|create|update|manage)',  # Express router
            r'@(?:Get|Post|Put|Delete|Patch)\s*\(["`\'][^"`\']*(?:admin|delete|create|update|manage)',  # NestJS decorators
            r'Route\.(?:get|post|put|delete|patch)\s*\(["`\'][^"`\']*(?:admin|delete|create|update|manage)',  # AdonisJS routes
            r'fastify\.(?:get|post|put|delete|patch)\s*\(["`\'][^"`\']*(?:admin|delete|create|update|manage)',  # Fastify routes
            r'server\.route\s*\(\s*\{[^}]*path.*(?:admin|delete|create|update|manage)',  # Hapi.js routes
        ]
        
        function_patterns = [
            r'function\s+(\w*(?:admin|delete|create|update|manage|grant|revoke)\w*)\s*\(',  # Function declarations
            r'const\s+(\w*(?:admin|delete|create|update|manage|grant|revoke)\w*)\s*=\s*(?:async\s+)?\(',  # Arrow functions
            r'(\w*(?:admin|delete|create|update|manage|grant|revoke)\w*)\s*:\s*(?:async\s+)?(?:function\s*)?\(',  # Object methods
        ]
        
        auth_patterns = [
            r'authenticate',
            r'authorize',
            r'checkAuth',
            r'requireAuth',
            r'isAuthenticated',
            r'hasRole',
            r'hasPermission',
            r'checkRole',
            r'checkPermission',
            r'middleware\.auth',
            r'auth\.check',
            r'jwt\.verify',
            r'passport\.authenticate',
            r'token\.verify',
            r'session\.user',
            r'user\.role',
            r'admin.*check',
            r'if.*role.*===.*admin',
            r'if.*permission',
            r'if.*authorized',
            r'guard\(',
            r'@UseGuards',
            r'@Roles',
            r'requiresAuth',
            r'protect\(',
            r'restrict\(',
        ]
        
        for i, line in enumerate(self.lines, 1):
            # Check for privileged route handlers
            for pattern in route_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Look for auth checks in surrounding lines
                    has_auth_check = False
                    context_start = max(0, i-10)
                    context_end = min(len(self.lines), i+30)
                    
                    for j in range(context_start, context_end):
                        check_line = self.lines[j]
                        if any(re.search(auth_pattern, check_line, re.IGNORECASE) for auth_pattern in auth_patterns):
                            has_auth_check = True
                            break
                    
                    if not has_auth_check:
                        vuln = self.create_vulnerability(
                            rule="js:S5144",
                            severity="HIGH",
                            line=i,
                            message=f"Potential broken access control: Privileged route/endpoint lacks proper authorization checks. Add authentication/authorization middleware.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "access-control"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
            
            # Check for privileged function handlers
            for pattern in function_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    function_name = match.group(1) if match.groups() else "unknown"
                    
                    # Look for auth checks in the next 20 lines
                    has_auth_check = False
                    for j in range(max(0, i-5), min(len(self.lines), i+20)):
                        check_line = self.lines[j]
                        if any(re.search(auth_pattern, check_line, re.IGNORECASE) for auth_pattern in auth_patterns):
                            has_auth_check = True
                            break
                    
                    if not has_auth_check:
                        vuln = self.create_vulnerability(
                            rule="js:S5144",
                            severity="HIGH",
                            line=i,
                            message=f"Potential broken access control: Function '{function_name}' appears to be privileged but lacks proper authorization checks.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "access-control"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
    
    def detect_xss_vulnerabilities(self):
        """Detect potential XSS vulnerabilities in JavaScript code"""
        # Dangerous DOM manipulation methods
        dangerous_dom_patterns = [
            r'\.innerHTML\s*=\s*(?![\'\"`])',  # innerHTML assignment with variables
            r'\.outerHTML\s*=\s*(?![\'\"`])',  # outerHTML assignment with variables
            r'document\.write\s*\(',  # document.write
            r'document\.writeln\s*\(',  # document.writeln
            r'eval\s*\(',  # eval() function
            r'Function\s*\(',  # Function() constructor
            r'setTimeout\s*\([^,)]*[^\'"`],[^)]*\)',  # setTimeout with string (not function)
            r'setInterval\s*\([^,)]*[^\'"`],[^)]*\)',  # setInterval with string
            r'\.insertAdjacentHTML\s*\(',  # insertAdjacentHTML
            r'\.html\s*\([^)]*\+',  # jQuery .html() with concatenation
            r'\$\([^)]*\)\.html\s*\([^)]*\+',  # jQuery .html() with concatenation
            r'React\.createElement\s*\([^,)]*,\s*\{[^}]*dangerouslySetInnerHTML',  # React dangerouslySetInnerHTML
            r'dangerouslySetInnerHTML\s*:',  # React dangerouslySetInnerHTML property
            r'v-html\s*=',  # Vue v-html directive
            r'\[innerHTML\]\s*=',  # Angular innerHTML binding
            r'\.setHTML\s*\(',  # Various framework setHTML methods
        ]
        
        # Template injection patterns
        template_patterns = [
            r'template\s*\(\s*[^)]*\+',  # Template with concatenation
            r'render\s*\(\s*[^)]*\+',  # Render with concatenation
            r'compile\s*\(\s*[^)]*\+',  # Template compile with concatenation
            r'\.template\s*=\s*[^\'"`]',  # Template assignment with variables
            r'Handlebars\.compile\s*\([^)]*\+',  # Handlebars with concatenation
            r'Mustache\.render\s*\([^)]*\+',  # Mustache with concatenation
            r'ejs\.render\s*\([^)]*\+',  # EJS with concatenation
            r'pug\.render\s*\([^)]*\+',  # Pug with concatenation
        ]
        
        # User input sources
        user_input_patterns = [
            r'req\.body',
            r'req\.query',
            r'req\.params',
            r'req\.headers',
            r'request\.body',
            r'ctx\.request',
            r'ctx\.query',
            r'this\.\$route\.query',
            r'this\.\$route\.params',
            r'useParams\(',
            r'useSearchParams\(',
            r'location\.search',
            r'window\.location',
            r'document\.location',
            r'document\.URL',
            r'document\.referrer',
            r'document\.cookie',
            r'localStorage\.getItem',
            r'sessionStorage\.getItem',
            r'URLSearchParams',
            r'new URL\(',
            r'props\.',
            r'this\.props\.',
            r'useState',
            r'userInput',
            r'input\.value',
            r'form\.value',
            r'\.value\b',
        ]
        
        # Response patterns (server-side)
        response_patterns = [
            r'res\.send\s*\(',
            r'res\.json\s*\(',
            r'res\.write\s*\(',
            r'res\.end\s*\(',
            r'response\.send\s*\(',
            r'ctx\.body\s*=',
            r'return.*res\(',
        ]
        
        for i, line in enumerate(self.lines, 1):
            # Check for dangerous DOM manipulation
            for pattern in dangerous_dom_patterns:
                if re.search(pattern, line):
                    # Check if user input is involved
                    context_lines = self.lines[max(0, i-3):min(len(self.lines), i+3)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_patterns)
                    has_concatenation = '+' in line or '${' in line
                    
                    if has_user_input or has_concatenation:
                        vuln = self.create_vulnerability(
                            rule="js:S5131",
                            severity="HIGH",
                            line=i,
                            message="Potential XSS vulnerability: User-controlled data is inserted into DOM without proper sanitization. Use textContent, sanitization libraries, or framework-specific safe methods.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "xss"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
            
            # Check for template injection
            for pattern in template_patterns:
                if re.search(pattern, line):
                    context_lines = self.lines[max(0, i-3):min(len(self.lines), i+3)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_patterns)
                    
                    if has_user_input:
                        vuln = self.create_vulnerability(
                            rule="js:S5131",
                            severity="HIGH",
                            line=i,
                            message="Potential template injection vulnerability: User input is used in template compilation/rendering without sanitization.",
                            vuln_type="VULNERABILITY",
                            effort="25min",
                            tags=["security", "xss", "template-injection"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
            
            # Check for unsafe response patterns
            for pattern in response_patterns:
                if re.search(pattern, line):
                    context_lines = self.lines[max(0, i-2):min(len(self.lines), i+2)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_patterns)
                    has_concatenation = '+' in line or '${' in line
                    
                    if has_user_input and has_concatenation:
                        vuln = self.create_vulnerability(
                            rule="js:S5131",
                            severity="MEDIUM",
                            line=i,
                            message="Potential XSS in server response: User input is sent to client without proper encoding/escaping. Ensure proper output encoding.",
                            vuln_type="VULNERABILITY",
                            effort="15min",
                            tags=["security", "xss"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
    
    def detect_insecure_deserialization(self):
        """Detect insecure deserialization vulnerabilities in JavaScript code"""
        dangerous_patterns = [
            r'JSON\.parse\s*\([^)]*req\.',  # JSON.parse with request data
            r'JSON\.parse\s*\([^)]*user',  # JSON.parse with user input
            r'eval\s*\(',  # eval() function
            r'Function\s*\([^)]*\+',  # Function constructor with concatenation
            r'new\s+Function\s*\(',  # new Function()
            r'vm\.runInThisContext\s*\(',  # Node.js vm module
            r'vm\.runInNewContext\s*\(',  # Node.js vm module
            r'require\s*\([^)]*\+',  # Dynamic require with user input
            r'import\s*\([^)]*\+',  # Dynamic import with user input
            r'\.deserialize\s*\(',  # General deserialization methods
            r'\.parse\s*\([^)]*req\.',  # Any .parse() with request data
            r'YAML\.parse\s*\(',  # YAML parsing
            r'yaml\.load\s*\(',  # YAML loading
            r'pickle\.loads\s*\(',  # Python-style pickle (if used in Node.js)
            r'unserialize\s*\(',  # PHP-style unserialize
            r'Buffer\.from\s*\([^)]*req\.',  # Buffer.from with request data
            r'atob\s*\([^)]*req\.',  # Base64 decode with request data
        ]
        
        user_input_sources = [
            r'req\.body',
            r'req\.query',
            r'req\.params',
            r'req\.headers',
            r'request\.body',
            r'ctx\.request',
            r'process\.argv',
            r'process\.env\.',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in dangerous_patterns:
                if re.search(pattern, line):
                    # Check if deserializing user input
                    context_lines = self.lines[max(0, i-3):min(len(self.lines), i+3)]
                    context = ' '.join(context_lines)
                    
                    has_user_input = any(re.search(input_pattern, context) for input_pattern in user_input_sources)
                    
                    if has_user_input or 'req.' in line or 'request.' in line or 'user' in line.lower():
                        severity = "BLOCKER" if "eval" in line or "Function" in line else "HIGH"
                        vuln = self.create_vulnerability(
                            rule="js:S5144",
                            severity=severity,
                            line=i,
                            message="Potential insecure deserialization: Deserializing user input without validation. Validate input structure and consider using safer alternatives.",
                            vuln_type="VULNERABILITY",
                            effort="30min",
                            tags=["security", "deserialization"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
        
        # Check for unsafe YAML loading specifically
        unsafe_yaml_patterns = [
            r'yaml\.load\s*\([^,)]*\)',  # yaml.load without safe option
            r'YAML\.load\s*\([^,)]*\)',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in unsafe_yaml_patterns:
                if re.search(pattern, line) and 'safeLoad' not in line and 'safe:' not in line:
                    vuln = self.create_vulnerability(
                        rule="js:S5144",
                        severity="HIGH",
                        line=i,
                        message="Unsafe YAML loading: yaml.load() can execute arbitrary code. Use yaml.safeLoad() or specify safe: true option.",
                        vuln_type="VULNERABILITY",
                        effort="10min",
                        tags=["security", "deserialization", "yaml"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def detect_unused_imports_variables(self):
        """Detect unused imports and variables in JavaScript code"""
        # Import patterns for different module systems
        import_patterns = [
            r'import\s+(\w+)\s+from',  # import name from 'module'
            r'import\s+\{\s*([^}]+)\s*\}\s+from',  # import { name1, name2 } from 'module'
            r'import\s+\*\s+as\s+(\w+)\s+from',  # import * as name from 'module'
            r'const\s+(\w+)\s*=\s*require\s*\(',  # const name = require()
            r'let\s+(\w+)\s*=\s*require\s*\(',  # let name = require()
            r'var\s+(\w+)\s*=\s*require\s*\(',  # var name = require()
            r'const\s+\{\s*([^}]+)\s*\}\s*=\s*require\s*\(',  # const { name } = require()
        ]
        
        imported_names = set()
        declared_variables = set()
        
        # Extract imported names
        for i, line in enumerate(self.lines, 1):
            for pattern in import_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    names = match.group(1)
                    if '{' in pattern and '}' in pattern:
                        # Handle destructured imports
                        for name in names.split(','):
                            name = name.strip()
                            # Handle aliases (name as alias)
                            if ' as ' in name:
                                name = name.split(' as ')[-1].strip()
                            imported_names.add((name, i))
                    else:
                        imported_names.add((names.strip(), i))
        
        # Extract variable declarations
        variable_patterns = [
            r'const\s+(\w+)\s*=',
            r'let\s+(\w+)\s*=',
            r'var\s+(\w+)\s*=',
            r'function\s+(\w+)\s*\(',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in variable_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_name = match.group(1)
                    declared_variables.add((var_name, i))
        
        # Remove imports and variable declarations from content to check usage
        content_no_imports = re.sub(r'import.*from.*[\'"`][^\'"`]+[\'"`]', '', self.content)
        content_no_imports = re.sub(r'const\s+\w+\s*=\s*require\s*\([^)]*\)', '', content_no_imports)
        content_no_imports = re.sub(r'(?:const|let|var)\s+\w+\s*=', '', content_no_imports)
        
        # Check for unused imports
        for name, line_num in imported_names:
            # Skip single character variables (likely used)
            if len(name) <= 1:
                continue
            
            # Check if name is used in the code
            usage_patterns = [
                rf'\b{re.escape(name)}\.',  # name.method()
                rf'\b{re.escape(name)}\(',  # name()
                rf'\b{re.escape(name)}\[',  # name[index]
                rf'\b{re.escape(name)}\s',  # name as standalone
                rf'<{re.escape(name)}\b',   # JSX components
                rf'</{re.escape(name)}>',   # JSX closing tags
            ]
            
            is_used = any(re.search(pattern, content_no_imports) for pattern in usage_patterns)
            
            if not is_used:
                vuln = self.create_vulnerability(
                    rule="js:F401",
                    severity="MINOR",
                    line=line_num,
                    message=f"Unused import '{name}'. Remove unused imports to improve code quality and reduce bundle size.",
                    vuln_type="CODE_SMELL",
                    effort="2min",
                    tags=["code-quality", "unused-code"]
                )
                self.vulnerabilities.append(vuln)
    
    def detect_invalid_redirects(self):
        """Detect invalid redirects and forwards in JavaScript code"""
        redirect_patterns = [
            r'res\.redirect\s*\([^)]*,?\s*([^,)]+)\)',  # Express res.redirect
            r'response\.redirect\s*\([^)]*,?\s*([^,)]+)\)',  # Generic response.redirect
            r'ctx\.redirect\s*\([^)]*,?\s*([^,)]+)\)',  # Koa ctx.redirect
            r'reply\.redirect\s*\([^)]*,?\s*([^,)]+)\)',  # Fastify reply.redirect
            r'window\.location\s*=\s*([^;]+)',  # Client-side window.location
            r'window\.location\.href\s*=\s*([^;]+)',  # Client-side href
            r'location\.href\s*=\s*([^;]+)',  # Client-side location.href
            r'document\.location\s*=\s*([^;]+)',  # Client-side document.location
            r'history\.push\s*\(\s*([^,)]+)',  # React Router history.push
            r'history\.replace\s*\(\s*([^,)]+)',  # React Router history.replace
            r'navigate\s*\(\s*([^,)]+)',  # React Router navigate
            r'router\.push\s*\(\s*([^,)]+)',  # Vue Router or Next.js router.push
            r'router\.replace\s*\(\s*([^,)]+)',  # Vue Router router.replace
            r'this\.\$router\.push\s*\(\s*([^,)]+)',  # Vue Router this.$router.push
            r'Router\.push\s*\(\s*([^,)]+)',  # Next.js Router.push
            r'useRouter\(\)\.push\s*\(\s*([^,)]+)',  # Next.js useRouter hook
        ]
        
        user_input_patterns = [
            r'req\.query',
            r'req\.params',
            r'req\.body',
            r'request\.query',
            r'ctx\.query',
            r'ctx\.params',
            r'this\.\$route\.query',
            r'useParams\(',
            r'useSearchParams\(',
            r'location\.search',
            r'window\.location\.search',
            r'URLSearchParams',
            r'query\.',
            r'params\.',
            r'props\.',
            r'state\.',
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
                    is_user_controlled = any(input_type in redirect_target.lower() for input_type in ['query', 'param', 'request', 'input', 'props', 'state'])
                    
                    if has_user_input or is_user_controlled:
                        vuln = self.create_vulnerability(
                            rule="js:S5146",
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
        """Detect insufficient logging and monitoring in JavaScript code"""
        # Check for logging imports/usage
        logging_patterns = [
            r'console\.log',
            r'console\.error',
            r'console\.warn',
            r'console\.info',
            r'console\.debug',
            r'logger\.',
            r'log\.',
            r'winston\.',
            r'bunyan\.',
            r'pino\.',
            r'morgan\(',
            r'debug\(',
        ]
        
        has_logging = any(
            any(re.search(pattern, line) for pattern in logging_patterns)
            for line in self.lines
        )
        
        security_events = ['login', 'logout', 'auth', 'permission', 'admin', 'access', 'session', 'token']
        
        # Find security-related functions
        function_patterns = [
            r'function\s+(\w*(?:' + '|'.join(security_events) + r')\w*)\s*\(',
            r'const\s+(\w*(?:' + '|'.join(security_events) + r')\w*)\s*=\s*(?:async\s+)?\(',
            r'(\w*(?:' + '|'.join(security_events) + r')\w*)\s*:\s*(?:async\s+)?(?:function\s*)?\(',
            r'\.(?:post|get|put|delete|patch)\s*\([\'"`][^\'"]*(?:' + '|'.join(security_events) + r')',
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in function_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    function_name = match.group(1) if match.groups() else "security endpoint"
                    
                    # Check if function contains logging calls in next 20 lines
                    has_log_call = False
                    for j in range(i, min(len(self.lines), i+20)):
                        check_line = self.lines[j]
                        if any(re.search(log_pattern, check_line) for log_pattern in logging_patterns):
                            has_log_call = True
                            break
                        # Break if we hit another function
                        if j > i and re.search(r'^\s*(?:function|const|let|var)\s+\w+', check_line):
                            break
                    
                    if not has_log_call:
                        vuln = self.create_vulnerability(
                            rule="js:S2629",
                            severity="MEDIUM",
                            line=i,
                            message=f"Insufficient logging: Security-related function/endpoint lacks proper logging. Add logging for security events to enable monitoring and incident response.",
                            vuln_type="CODE_SMELL",
                            effort="10min",
                            tags=["security", "logging"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
        
        # Check for error handling without logging
        error_patterns = [
            r'catch\s*\(\s*\w+\s*\)\s*\{[^}]*\}',  # catch block
            r'\.catch\s*\(\s*\w+\s*=>\s*\{[^}]*\}',  # Promise catch
            r'if\s*\(\s*err\s*\)',  # Error condition
            r'if\s*\(\s*error\s*\)',  # Error condition
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in error_patterns:
                if re.search(pattern, line):
                    # Check if there's logging in the error handling block
                    context_lines = self.lines[i-1:min(len(self.lines), i+10)]
                    context = ' '.join(context_lines)
                    
                    has_logging = any(re.search(log_pattern, context) for log_pattern in logging_patterns)
                    
                    if not has_logging and 'log' not in context.lower():
                        vuln = self.create_vulnerability(
                            rule="js:S2629",
                            severity="LOW",
                            line=i,
                            message="Error handling without logging: Errors should be logged for debugging and monitoring purposes.",
                            vuln_type="CODE_SMELL",
                            effort="5min",
                            tags=["logging", "error-handling"]
                        )
                        self.vulnerabilities.append(vuln)
                        break
    
    def detect_vulnerable_dependencies(self):
        """Detect vulnerable and outdated components in JavaScript packages"""
        # Check for package.json file
        project_dir = os.path.dirname(self.file_path)
        package_json_path = os.path.join(project_dir, 'package.json')
        yarn_lock_path = os.path.join(project_dir, 'yarn.lock')
        package_lock_path = os.path.join(project_dir, 'package-lock.json')
        
        # Common packages with known vulnerabilities (simplified check)
        known_vulnerabilities = {
            'lodash': '4.17.21',
            'axios': '0.21.2',
            'express': '4.17.3',
            'react': '17.0.2',
            'vue': '3.2.31',
            'jquery': '3.6.0',
            'moment': '2.29.4',  # Deprecated, should use dayjs or date-fns
            'request': '2.88.2',  # Deprecated
            'handlebars': '4.7.7',
            'ejs': '3.1.6',
            'pug': '3.0.2',
            'socket.io': '4.4.1',
            'ws': '8.5.0',
            'jsonwebtoken': '8.5.1',
            'bcrypt': '5.0.1',
            'helmet': '5.0.2',
            'cors': '2.8.5',
        }
        
        deprecated_packages = [
            'request',  # Use axios, node-fetch, or native fetch
            'moment',   # Use dayjs or date-fns
            'bower',    # Use npm or yarn
            'gulp',     # Use webpack, parcel, or vite
            'grunt',    # Use webpack, parcel, or vite
        ]
        
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, 'r') as f:
                    content = f.read()
                
                for package, min_version in known_vulnerabilities.items():
                    if f'"{package}"' in content:
                        vuln = self.create_vulnerability(
                            rule="js:S4830",
                            severity="HIGH",
                            line=1,
                            message=f"Potentially vulnerable dependency detected: '{package}'. Ensure you're using version >= {min_version} or the latest secure version.",
                            vuln_type="VULNERABILITY",
                            effort="10min",
                            tags=["security", "dependencies"]
                        )
                        self.vulnerabilities.append(vuln)
                
                for deprecated_pkg in deprecated_packages:
                    if f'"{deprecated_pkg}"' in content:
                        vuln = self.create_vulnerability(
                            rule="js:S4830",
                            severity="MEDIUM",
                            line=1,
                            message=f"Deprecated package detected: '{deprecated_pkg}'. Update to the recommended alternative for better security and maintenance.",
                            vuln_type="CODE_SMELL",
                            effort="15min",
                            tags=["security", "deprecated"]
                        )
                        self.vulnerabilities.append(vuln)
                        
            except Exception:
                pass
        
        # Check for unsafe Node.js patterns
        unsafe_node_patterns = [
            r'child_process\.exec\s*\([^)]*\+',  # Command injection via exec
            r'child_process\.spawn\s*\([^)]*\+',  # Command injection via spawn
            r'eval\s*\(',  # Code execution
            r'Function\s*\(',  # Code execution via Function constructor
            r'require\s*\([^)]*\+',  # Dynamic require with user input
            r'process\.env\.[A-Z_]+\s*\|\|\s*[\'"`][^\'"`]*[\'"`]',  # Hardcoded fallbacks for env vars
            r'fs\.readFile\s*\([^)]*\+',  # Path traversal via file operations
            r'fs\.writeFile\s*\([^)]*\+',  # Path traversal via file operations
            r'path\.join\s*\([^)]*req\.',  # Path traversal via path.join with user input
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern in unsafe_node_patterns:
                if re.search(pattern, line):
                    if 'child_process' in pattern:
                        severity = "BLOCKER"
                        message = "Command injection vulnerability: User input is passed to child_process methods. Validate and sanitize all input, use array syntax instead of string concatenation."
                    elif 'eval' in pattern or 'Function' in pattern:
                        severity = "BLOCKER"
                        message = "Code execution vulnerability: eval() or Function() constructor can execute arbitrary code. Avoid dynamic code execution."
                    elif 'fs\.' in pattern:
                        severity = "HIGH"
                        message = "Path traversal vulnerability: File system operations with user input can lead to unauthorized file access. Validate and sanitize file paths."
                    else:
                        severity = "MEDIUM"
                        message = "Potentially unsafe operation: User input may be used in sensitive operations without proper validation."
                    
                    vuln = self.create_vulnerability(
                        rule="js:S4830",
                        severity=severity,
                        line=i,
                        message=message,
                        vuln_type="VULNERABILITY",
                        effort="20min",
                        tags=["security", "injection"]
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
    """Scan a single JavaScript file for vulnerabilities"""
    detector = JSVulnerabilityDetector(file_path)
    return detector.run_all_detections()

def scan_directory(directory: str) -> List[Dict]:
    """Scan all JavaScript files in a directory"""
    all_vulnerabilities = []
    
    # JavaScript file extensions
    js_extensions = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.mjs', '.cjs']
    
    for root, dirs, files in os.walk(directory):
        # Skip node_modules and other common directories
        dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', 'dist', 'build', 'coverage']]
        
        for file in files:
            if any(file.endswith(ext) for ext in js_extensions):
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
        print("Usage: python js_vuln_scanner.py <file_or_directory> [output_file.json]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "js_vulnerabilities.json"
    
    vulnerabilities = []
    
    # Check if target is a JavaScript file
    js_extensions = ['.js', '.jsx', '.ts', '.tsx', '.vue', '.mjs', '.cjs']
    
    if os.path.isfile(target) and any(target.endswith(ext) for ext in js_extensions):
        vulnerabilities = scan_file(target)
    elif os.path.isdir(target):
        vulnerabilities = scan_directory(target)
    else:
        print(f"Error: {target} is not a valid JavaScript file or directory")
        sys.exit(1)
    
    # Save results to JSON file
    with open(output_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
    
    print(f"JavaScript vulnerability scan completed. Found {len(vulnerabilities)} potential vulnerabilities.")
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
        print("\n✅ No vulnerabilities found! Your JavaScript code looks secure.")

if __name__ == "__main__":
    main()