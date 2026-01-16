#!/usr/bin/env python3
"""
Python Vulnerability Scanner
Detects common security vulnerabilities in Python code and generates JSON reports.
"""

import ast
import re
import json
import hashlib
import os
import sys
from datetime import datetime
from typing import List, Dict, Any, Set, Tuple
import pkg_resources
from packaging import version
import requests
import time

class VulnerabilityDetector:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.project_name = os.path.basename(os.path.dirname(file_path))
        self.component_name = f"{self.project_name}:{os.path.relpath(file_path)}"
        self.vulnerabilities = []
        
        # Read file content
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.content = f.read()
        
        # Parse AST
        try:
            self.tree = ast.parse(self.content)
        except SyntaxError as e:
            print(f"Syntax error in {file_path}: {e}")
            self.tree = None
        
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
        """Detect potential SQL injection vulnerabilities"""
        if not self.tree:
            return
            
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER']
        dangerous_patterns = [
            r'["\'].*?\+.*?["\']',  # String concatenation in queries
            r'\.format\s*\(',       # .format() in SQL strings
            r'%\s*["\']',          # % formatting in SQL strings
            r'f["\'].*?{.*?}.*?["\']'  # f-strings with variables
        ]
        
        class SQLVisitor(ast.NodeVisitor):
            def __init__(self, detector):
                self.detector = detector
                self.in_sql_context = False
                
            def visit_Str(self, node):
                if isinstance(node.s, str) and any(keyword in node.s.upper() for keyword in sql_keywords):
                    line_num = node.lineno
                    line_content = self.detector.lines[line_num - 1] if line_num <= len(self.detector.lines) else ""
                    
                    # Check for dangerous patterns
                    if any(re.search(pattern, line_content, re.IGNORECASE) for pattern in dangerous_patterns):
                        vuln = self.detector.create_vulnerability(
                            rule="python:S2077",
                            severity="BLOCKER",
                            line=line_num,
                            message="Potential SQL injection vulnerability detected. Use parameterized queries instead of string concatenation.",
                            vuln_type="VULNERABILITY",
                            effort="30min",
                            tags=["security", "sql-injection"]
                        )
                        self.detector.vulnerabilities.append(vuln)
                
            def visit_Call(self, node):
                # Check for execute() calls with string formatting
                if (hasattr(node.func, 'attr') and node.func.attr == 'execute' and 
                    node.args and len(node.args) > 0):
                    
                    arg = node.args[0]
                    line_num = node.lineno
                    line_content = self.detector.lines[line_num - 1] if line_num <= len(self.detector.lines) else ""
                    
                    # Check for string formatting in execute calls
                    if (isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod) or
                        isinstance(arg, ast.Call) and hasattr(arg.func, 'attr') and arg.func.attr == 'format'):
                        
                        vuln = self.detector.create_vulnerability(
                            rule="python:S2077",
                            severity="BLOCKER", 
                            line=line_num,
                            message="SQL injection vulnerability: Use parameterized queries instead of string formatting in database execute() calls.",
                            vuln_type="VULNERABILITY",
                            effort="30min",
                            tags=["security", "sql-injection"]
                        )
                        self.detector.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = SQLVisitor(self)
        visitor.visit(self.tree)
    
    def detect_hardcoded_secrets(self):
        """Detect hardcoded passwords, API keys, and secrets"""
        if not self.tree:
            return
            
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password detected"),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key detected"),
            (r'secret[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded secret key detected"),
            (r'access[_-]?token\s*=\s*["\'][^"\']+["\']', "Hardcoded access token detected"),
            (r'aws[_-]?access[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded AWS access key detected"),
            (r'database[_-]?url\s*=\s*["\'].*://.*:[^@]+@.*["\']', "Database URL with embedded credentials detected"),
        ]
        
        for i, line in enumerate(self.lines, 1):
            for pattern, message in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    vuln = self.create_vulnerability(
                        rule="python:S2068",
                        severity="BLOCKER",
                        line=i,
                        message=message + ". Use environment variables or secure configuration management instead.",
                        vuln_type="VULNERABILITY",
                        effort="15min",
                        tags=["security", "credentials"]
                    )
                    self.vulnerabilities.append(vuln)
    
    def detect_broken_access_control(self):
        """Detect potential broken access control issues"""
        if not self.tree:
            return
            
        class AccessControlVisitor(ast.NodeVisitor):
            def __init__(self, detector):
                self.detector = detector
                
            def visit_FunctionDef(self, node):
                # Check for admin/privileged functions without proper authorization checks
                if any(keyword in node.name.lower() for keyword in ['admin', 'delete', 'create_user', 'grant', 'revoke']):
                    # Look for authorization decorators or checks
                    has_auth_decorator = any(
                        hasattr(decorator, 'id') and decorator.id in ['login_required', 'admin_required', 'permission_required']
                        for decorator in node.decorator_list
                        if hasattr(decorator, 'id')
                    )
                    
                    # Look for permission checks in function body
                    has_permission_check = False
                    for stmt in node.body:
                        if isinstance(stmt, ast.If):
                            # Check if condition involves permission/authorization
                            condition_str = ast.unparse(stmt.test) if hasattr(ast, 'unparse') else str(stmt.test)
                            if any(keyword in condition_str.lower() for keyword in ['permission', 'authorized', 'admin', 'role']):
                                has_permission_check = True
                                break
                    
                    if not has_auth_decorator and not has_permission_check:
                        vuln = self.detector.create_vulnerability(
                            rule="python:S5144",
                            severity="HIGH",
                            line=node.lineno,
                            message=f"Potential broken access control: Function '{node.name}' appears to be privileged but lacks proper authorization checks.",
                            vuln_type="VULNERABILITY",
                            effort="20min",
                            tags=["security", "access-control"]
                        )
                        self.detector.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = AccessControlVisitor(self)
        visitor.visit(self.tree)
    
    def detect_xss_vulnerabilities(self):
        """Detect potential XSS vulnerabilities"""
        if not self.tree:
            return
            
        dangerous_functions = [
            'render_template_string',
            'Markup',
            'send_from_directory'
        ]
        
        class XSSVisitor(ast.NodeVisitor):
            def __init__(self, detector):
                self.detector = detector
                
            def visit_Call(self, node):
                # Check for dangerous template rendering functions
                func_name = ""
                if hasattr(node.func, 'id'):
                    func_name = node.func.id
                elif hasattr(node.func, 'attr'):
                    func_name = node.func.attr
                
                if func_name in dangerous_functions:
                    # Check if user input is being passed without sanitization
                    vuln = self.detector.create_vulnerability(
                        rule="python:S5131",
                        severity="HIGH",
                        line=node.lineno,
                        message=f"Potential XSS vulnerability: '{func_name}' called with potentially unsanitized input. Ensure proper input validation and output encoding.",
                        vuln_type="VULNERABILITY",
                        effort="25min",
                        tags=["security", "xss"]
                    )
                    self.detector.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = XSSVisitor(self)
        visitor.visit(self.tree)
    
    def detect_insecure_deserialization(self):
        """Detect insecure deserialization vulnerabilities"""
        if not self.tree:
            return
            
        dangerous_modules = ['pickle', 'cPickle', 'dill', 'yaml']
        dangerous_functions = ['loads', 'load', 'Unpickler']
        
        class DeserializationVisitor(ast.NodeVisitor):
            def __init__(self, detector):
                self.detector = detector
                
            def visit_Call(self, node):
                # Check for dangerous deserialization calls
                func_name = ""
                module_name = ""
                
                if hasattr(node.func, 'attr'):
                    func_name = node.func.attr
                    if hasattr(node.func.value, 'id'):
                        module_name = node.func.value.id
                
                if module_name in dangerous_modules and func_name in dangerous_functions:
                    vuln = self.detector.create_vulnerability(
                        rule="python:S5144",
                        severity="BLOCKER",
                        line=node.lineno,
                        message=f"Insecure deserialization vulnerability: '{module_name}.{func_name}' can execute arbitrary code. Use safer alternatives like json or validate input source.",
                        vuln_type="VULNERABILITY", 
                        effort="30min",
                        tags=["security", "deserialization"]
                    )
                    self.detector.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = DeserializationVisitor(self)
        visitor.visit(self.tree)
    
    def detect_unused_imports_variables(self):
        """Detect unused imports and variables"""
        if not self.tree:
            return
            
        imported_names = set()
        used_names = set()
        defined_variables = set()
        
        class ImportVisitor(ast.NodeVisitor):
            def visit_Import(self, node):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imported_names.add((name, node.lineno))
            
            def visit_ImportFrom(self, node):
                for alias in node.names:
                    name = alias.asname if alias.asname else alias.name
                    imported_names.add((name, node.lineno))
        
        class NameVisitor(ast.NodeVisitor):
            def visit_Name(self, node):
                if isinstance(node.ctx, ast.Load):
                    used_names.add(node.id)
                elif isinstance(node.ctx, ast.Store):
                    defined_variables.add((node.id, node.lineno))
        
        import_visitor = ImportVisitor()
        import_visitor.visit(self.tree)
        
        name_visitor = NameVisitor()
        name_visitor.visit(self.tree)
        
        # Check for unused imports
        for name, line_num in imported_names:
            if name not in used_names and not name.startswith('_'):
                vuln = self.create_vulnerability(
                    rule="python:F401",
                    severity="MINOR",
                    line=line_num,
                    message=f"Unused import '{name}'. Remove unused imports to improve code quality and reduce attack surface.",
                    vuln_type="CODE_SMELL",
                    effort="2min",
                    tags=["code-quality", "unused-code"]
                )
                self.vulnerabilities.append(vuln)
    
    def detect_invalid_redirects(self):
        """Detect invalid redirects and forwards"""
        if not self.tree:
            return
            
        redirect_functions = ['redirect', 'url_for']
        
        class RedirectVisitor(ast.NodeVisitor):
            def __init__(self, detector):
                self.detector = detector
                
            def visit_Call(self, node):
                func_name = ""
                if hasattr(node.func, 'id'):
                    func_name = node.func.id
                elif hasattr(node.func, 'attr'):
                    func_name = node.func.attr
                
                if func_name in redirect_functions and node.args:
                    # Check if redirect URL comes from user input
                    arg = node.args[0]
                    if isinstance(arg, ast.Name) or isinstance(arg, ast.Subscript):
                        # Potential user-controlled redirect
                        vuln = self.detector.create_vulnerability(
                            rule="python:S5146",
                            severity="MEDIUM",
                            line=node.lineno,
                            message=f"Potential unvalidated redirect: '{func_name}' called with user-controlled input. Validate and whitelist redirect URLs to prevent phishing attacks.",
                            vuln_type="VULNERABILITY",
                            effort="15min",
                            tags=["security", "redirect"]
                        )
                        self.detector.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = RedirectVisitor(self)
        visitor.visit(self.tree)
    
    def detect_insufficient_logging(self):
        """Detect insufficient logging and monitoring"""
        if not self.tree:
            return
            
        has_logging = False
        security_events = ['login', 'logout', 'authentication', 'authorization', 'permission', 'access']
        
        class LoggingVisitor(ast.NodeVisitor):
            def __init__(self, detector):
                self.detector = detector
                self.has_logging_import = False
                self.security_functions = []
                
            def visit_Import(self, node):
                for alias in node.names:
                    if alias.name in ['logging', 'log']:
                        self.has_logging_import = True
            
            def visit_ImportFrom(self, node):
                if node.module in ['logging', 'log']:
                    self.has_logging_import = True
            
            def visit_FunctionDef(self, node):
                # Check if security-related functions have logging
                if any(event in node.name.lower() for event in security_events):
                    self.security_functions.append((node.name, node.lineno))
                    
                    # Check if function contains logging calls
                    has_log_call = False
                    for stmt in ast.walk(node):
                        if isinstance(stmt, ast.Call):
                            if (hasattr(stmt.func, 'attr') and 
                                stmt.func.attr in ['debug', 'info', 'warning', 'error', 'critical']):
                                has_log_call = True
                                break
                    
                    if not has_log_call:
                        vuln = self.detector.create_vulnerability(
                            rule="python:S2629",
                            severity="MEDIUM",
                            line=node.lineno,
                            message=f"Insufficient logging: Security-related function '{node.name}' lacks proper logging. Add logging for security events to enable monitoring and incident response.",
                            vuln_type="CODE_SMELL",
                            effort="10min",
                            tags=["security", "logging"]
                        )
                        self.detector.vulnerabilities.append(vuln)
                
                self.generic_visit(node)
        
        visitor = LoggingVisitor(self)
        visitor.visit(self.tree)
    
    def detect_vulnerable_dependencies(self):
        """Detect vulnerable and outdated components (basic check)"""
        # This is a simplified version - in practice, you'd want to integrate with a vulnerability database
        requirements_patterns = [
            'requirements.txt',
            'requirements-dev.txt', 
            'requirements-prod.txt',
            'setup.py',
            'pyproject.toml'
        ]
        
        # Check if requirements file exists in project directory
        project_dir = os.path.dirname(self.file_path)
        for req_file in requirements_patterns:
            req_path = os.path.join(project_dir, req_file)
            if os.path.exists(req_path):
                # Basic check for common vulnerable packages (this is simplified)
                known_vulnerabilities = {
                    'django': '4.0.0',  # Example: versions below 4.0.0 might have vulnerabilities
                    'flask': '2.0.0',
                    'requests': '2.25.0',
                    'pillow': '8.1.1',
                    'pyyaml': '5.4.0'
                }
                
                try:
                    with open(req_path, 'r') as f:
                        content = f.read()
                        
                    for pkg, min_version in known_vulnerabilities.items():
                        if pkg in content.lower():
                            vuln = self.create_vulnerability(
                                rule="python:S4830",
                                severity="HIGH",
                                line=1,
                                message=f"Potentially vulnerable dependency detected: '{pkg}'. Ensure you're using the latest secure version (>= {min_version}).",
                                vuln_type="VULNERABILITY",
                                effort="10min",
                                tags=["security", "dependencies"]
                            )
                            self.vulnerabilities.append(vuln)
                            break
                except:
                    pass
    
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
    """Scan a single Python file for vulnerabilities"""
    detector = VulnerabilityDetector(file_path)
    return detector.run_all_detections()

def scan_directory(directory: str) -> List[Dict]:
    """Scan all Python files in a directory"""
    all_vulnerabilities = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
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
        print("Usage: python vuln_scanner.py <file_or_directory> [output_file.json]")
        sys.exit(1)
    
    target = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "vulnerabilities.json"
    
    vulnerabilities = []
    
    if os.path.isfile(target) and target.endswith('.py'):
        vulnerabilities = scan_file(target)
    elif os.path.isdir(target):
        vulnerabilities = scan_directory(target)
    else:
        print(f"Error: {target} is not a valid Python file or directory")
        sys.exit(1)
    
    # Save results to JSON file
    with open(output_file, 'w') as f:
        json.dump(vulnerabilities, f, indent=2)
    
    print(f"Scan completed. Found {len(vulnerabilities)} potential vulnerabilities.")
    print(f"Results saved to {output_file}")
    
    # Print summary
    if vulnerabilities:
        severity_counts = {}
        type_counts = {}
        
        for vuln in vulnerabilities:
            severity = vuln['severity']
            vuln_type = vuln['type']
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
        
        print("\nSummary:")
        print("By Severity:")
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity}: {count}")
        
        print("\nBy Type:")
        for vuln_type, count in sorted(type_counts.items()):
            print(f"  {vuln_type}: {count}")

if __name__ == "__main__":
    main()