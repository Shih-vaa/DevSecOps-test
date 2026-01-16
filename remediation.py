#!/usr/bin/env python3
"""
AI-Powered Security Remediation Pipeline
Integrates with Groq API to automatically fix vulnerabilities detected by SonarQube
Enhanced with robust code extraction for multiple programming languages
"""

import os
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path
import asyncio
from groq import Groq
from datetime import datetime
import re

# modelname = 'qwen/qwen3-32b'  # Default model for Groq API
# modelname = 'llama3-70b-8192'
modelname = 'llama-3.3-70b-versatile'

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class SonarIssue:
    """Represents a SonarQube security issue"""
    key: str
    rule: str
    severity: str
    component: str
    project: str
    line: int
    hash: str
    text_range: Dict
    flows: List
    message: str
    effort: str
    debt: str
    assignee: str
    author: str
    tags: List[str]
    type: str
    scope: str
    quickFixAvailable: bool
    messageFormattings: List

@dataclass
class RemediationResult:
    """Represents the result of AI remediation"""
    original_file: str
    secure_file: str
    issues_fixed: List[str]
    confidence_score: float
    timestamp: datetime
    model_used: str

class CodeExtractor:
    """Enhanced code extraction utility for multiple programming languages"""
    
    # Common programming language file extensions and their identifiers
    LANGUAGE_MAP = {
        '.py': 'python',
        '.java': 'java',
        '.js': 'javascript',
        '.jsx': 'jsx',
        '.ts': 'typescript',
        '.tsx': 'tsx',
        '.php': 'php',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.go': 'go',
        '.rb': 'ruby',
        '.rs': 'rust',
        '.kt': 'kotlin',
        '.scala': 'scala',
        '.swift': 'swift',
        '.m': 'objective-c',
        '.pl': 'perl',
        '.r': 'r',
        '.sql': 'sql',
        '.sh': 'bash',
        '.ps1': 'powershell',
        '.vb': 'vb',
        '.html': 'html',
        '.css': 'css',
        '.xml': 'xml',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.json': 'json'
    }
    
    def __init__(self, file_extension: str = None):
        self.file_extension = file_extension.lower() if file_extension else None
        self.language = self.LANGUAGE_MAP.get(self.file_extension, 'text')
    
    def extract_clean_code(self, llm_output: str) -> str:
        """
        Extract clean code from LLM output, removing all non-code content
        
        Args:
            llm_output: Raw output from the LLM
            
        Returns:
            Clean code without explanations, tags, or markdown
        """
        if not llm_output or not llm_output.strip():
            return ""
        
        # Step 1: Remove XML-like tags (e.g., <Think>, <Analysis>, etc.)
        cleaned_output = self._remove_xml_tags(llm_output)
        
        # Step 2: Extract code from markdown code blocks
        code_from_blocks = self._extract_from_code_blocks(cleaned_output)
        if code_from_blocks:
            return code_from_blocks
        
        # Step 3: Remove common LLM explanation patterns
        code_without_explanations = self._remove_explanations(cleaned_output)
        
        # Step 4: Detect and extract code sections
        final_code = self._extract_code_sections(code_without_explanations)
        
        return final_code.strip()
    
    def _remove_xml_tags(self, text: str) -> str:
        """Remove XML-like tags and their content"""
        # Remove tags like <Think>, <Analysis>, </Think>, etc.
        xml_pattern = r'</?[A-Za-z][A-Za-z0-9]*[^>]*>'
        cleaned = re.sub(xml_pattern, '', text, flags=re.IGNORECASE)
        
        # Remove content between specific tags that commonly contain explanations
        explanation_tags = ['think', 'analysis', 'explanation', 'reasoning', 'note', 'comment']
        for tag in explanation_tags:
            pattern = rf'<{tag}[^>]*>.*?</{tag}>'
            cleaned = re.sub(pattern, '', cleaned, flags=re.DOTALL | re.IGNORECASE)
        
        return cleaned
    
    def _extract_from_code_blocks(self, text: str) -> Optional[str]:
        """Extract code from markdown code blocks"""
        # Pattern for code blocks with language specification
        patterns = [
            rf'```{self.language}\s*\n(.*?)\n```',  # Specific language
            rf'```\w*\s*\n(.*?)\n```',              # Any language
            r'```\s*\n(.*?)\n```',                   # No language specified
            r'`{3,}\s*\n(.*?)\n`{3,}',              # Variable backticks
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
            if matches:
                # Return the longest code block (most likely the main code)
                return max(matches, key=len).strip()
        
        return None
    
    def _remove_explanations(self, text: str) -> str:
        """Remove common explanation patterns from LLM output"""
        # Patterns that typically indicate explanations rather than code
        explanation_patterns = [
            r'^(Here\'s|Here is|This is|The following|Below is).*?:?\s*\n',
            r'^(I\'ve|I have|I will|Let me|Now I|First,).*?\n',
            r'^(The code|This code|Above code|Fixed code).*?\n',
            r'^(Explanation|Analysis|Summary|Note).*?:\s*\n',
            r'^(As you can see|Notice that|Important).*?\n',
            r'\n\n(Explanation|Analysis|Summary|Note).*?$',
            r'\n\n(The above|This solution|The fix).*?$',
        ]
        
        cleaned_text = text
        for pattern in explanation_patterns:
            cleaned_text = re.sub(pattern, '', cleaned_text, flags=re.MULTILINE | re.IGNORECASE)
        
        return cleaned_text
    
    def _extract_code_sections(self, text: str) -> str:
        """Extract sections that look like code based on programming patterns"""
        lines = text.split('\n')
        code_lines = []
        
        # Language-specific patterns for code detection
        code_indicators = self._get_code_indicators()
        
        in_code_section = False
        explanation_keywords = [
            'explanation', 'analysis', 'summary', 'note', 'description',
            'here\'s', 'here is', 'this is', 'the following', 'below is',
            'i\'ve', 'i have', 'i will', 'let me', 'now i', 'first,',
            'the code', 'this code', 'above code', 'fixed code',
            'as you can see', 'notice that', 'important'
        ]
        
        for line in lines:
            line_lower = line.strip().lower()
            
            # Skip obvious explanation lines
            if any(keyword in line_lower for keyword in explanation_keywords):
                in_code_section = False
                continue
            
            # Check if line looks like code
            if self._looks_like_code(line, code_indicators):
                in_code_section = True
                code_lines.append(line)
            elif in_code_section and (line.strip() == '' or line.startswith((' ', '\t'))):
                # Include empty lines or indented lines when in code section
                code_lines.append(line)
            elif not line.strip():
                # Include empty lines
                code_lines.append(line)
            else:
                # Reset code section flag for non-code lines
                in_code_section = False
        
        return '\n'.join(code_lines).strip()
    
    def _get_code_indicators(self) -> List[str]:
        """Get language-specific patterns that indicate code"""
        common_indicators = [
            r'^\s*#',           # Comments
            r'^\s*//',          # Comments
            r'^\s*/\*',         # Block comments
            r'^\s*\*',          # Block comment continuation
            r'=\s*[\'"`]',      # Assignment with quotes
            r'[;{}()]',         # Common code symbols
            r'^\s*\w+\s*\(',    # Function calls
            r'^\s*(if|for|while|def|function|class|public|private|protected)\s',
        ]
        
        language_specific = {
            'python': [r'^\s*(def|class|import|from|if|elif|else|for|while|try|except|with)\s',
                      r':\s*$', r'^\s*@\w+'],
            'java': [r'^\s*(public|private|protected|static|final|abstract|class|interface)\s',
                    r'^\s*import\s', r'^\s*package\s'],
            'javascript': [r'^\s*(function|var|let|const|if|else|for|while|class)\s',
                          r'^\s*(import|export)\s', r'=>'],
            'php': [r'^\s*<\?php', r'^\s*\$\w+', r'^\s*(function|class|if|else|foreach|while)\s'],
            'c': [r'^\s*#include', r'^\s*(int|char|float|double|void|struct)\s'],
            'cpp': [r'^\s*#include', r'^\s*(int|char|float|double|void|class|struct)\s',
                   r'^\s*using\s+namespace'],
        }
        
        indicators = common_indicators[:]
        if self.language in language_specific:
            indicators.extend(language_specific[self.language])
        
        return indicators
    
    def _looks_like_code(self, line: str, indicators: List[str]) -> bool:
        """Determine if a line looks like code"""
        if not line.strip():
            return False
        
        # Check against language-specific indicators
        for pattern in indicators:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        
        # General heuristics for code detection
        stripped = line.strip()
        
        # Lines with specific code characteristics
        code_characteristics = [
            len(re.findall(r'[{}();,]', stripped)) >= 1,  # Code symbols
            '=' in stripped and not stripped.startswith(('=', '==')),  # Assignment
            stripped.endswith((':',)),  # Python/YAML style
            stripped.endswith((';',)),  # C-style languages
            re.search(r'\w+\s*\(.*\)', stripped),  # Function calls
            stripped.startswith(('@', '#', '//')),  # Decorators/comments
        ]
        
        return any(code_characteristics)

class SonarQubeIssueParser:
    """Parses SonarQube JSON issues into structured format"""
    
    @staticmethod
    def parse_issues(sonar_json: Dict) -> List[SonarIssue]:
        """Parse SonarQube JSON response into SonarIssue objects"""
        issues = []
        
        # Support both object-with-issues and raw list formats
        if isinstance(sonar_json, list):
            issues_iterable = sonar_json
        else:
            issues_iterable = sonar_json.get('issues', [])
        
        for issue_data in issues_iterable:
            try:
                issue = SonarIssue(
                    key=issue_data.get('key', ''),
                    rule=issue_data.get('rule', ''),
                    severity=issue_data.get('severity', ''),
                    component=issue_data.get('component', ''),
                    project=issue_data.get('project', ''),
                    line=issue_data.get('line', 0),
                    hash=issue_data.get('hash', ''),
                    text_range=issue_data.get('textRange', {}),
                    flows=issue_data.get('flows', []),
                    message=issue_data.get('message', ''),
                    effort=issue_data.get('effort', ''),
                    debt=issue_data.get('debt', ''),
                    assignee=issue_data.get('assignee', ''),
                    author=issue_data.get('author', ''),
                    tags=issue_data.get('tags', []),
                    type=issue_data.get('type', ''),
                    scope=issue_data.get('scope', ''),
                    quickFixAvailable=issue_data.get('quickFixAvailable', False),
                    messageFormattings=issue_data.get('messageFormattings', [])
                )
                issues.append(issue)
            except Exception as e:
                logger.error(f"Error parsing issue: {e}")
                continue
                
        return issues

class GroqSecurityRemediator:
    """AI-powered security remediation using Groq API"""
    
    def __init__(self, api_key: str, model: str = modelname):
        """
        Initialize the Groq Security Remediator
        
        Args:
            api_key: Groq API key
            model: Groq model to use for remediation
        """
        self.client = Groq(api_key=api_key)
        self.model = model
        self.max_retries = 3
        self.retry_delay = 1
        
    def _create_remediation_prompt(self, vulnerable_code: str, issues: List[SonarIssue], file_extension: str = None) -> str:
        """Create a detailed prompt for AI remediation"""

        # Group issues by type and severity
        security_issues = []
        for issue in issues:
            issue_info = {
                'rule': issue.rule,
                'severity': issue.severity,
                'message': issue.message,
                'line': issue.line,
                'type': issue.type,
                'tags': issue.tags
            }
            security_issues.append(issue_info)

        # Determine language context
        language_context = ""
        if file_extension:
            lang_map = CodeExtractor.LANGUAGE_MAP
            language = lang_map.get(file_extension.lower(), 'unknown')
            language_context = f"This is {language} code. "

        prompt = f"""ROLE: Senior application security engineer.

GOAL: Produce a single, runnable, self-contained file that fixes all vulnerabilities without changing intended behavior.

{language_context}

SOURCE (vulnerable) CODE:
{vulnerable_code}

ISSUES FROM ANALYZER:
{json.dumps(security_issues, indent=2)}

ALSO VERIFY AND FIX IF PRESENT:
- SQL Injection
- Broken Access Control
- Hardcoded passwords/keys/secrets
- Vulnerable/outdated components (libraries, frameworks)
- Cross-Site Scripting (XSS)
- Insufficient logging/monitoring for security-relevant paths
- Insecure Deserialization
- Unused imports, variables, dead code
- Invalid redirects and forwards

STRICT REQUIREMENTS:
1. Preserve original behavior and intent; keep public function names and route paths when safe.
2. Include all required imports and definitions. Do not reference undefined names.
3. Remove unused imports and dead code.
4. SQL must use parameterized queries (never string interpolation).
5. Secrets must be read from environment variables (no hardcoded secrets).
6. Escape untrusted output for HTML to prevent XSS.
7. Validate redirect targets using an allowlist or same-origin check.
8. Replace insecure deserialization (e.g., pickle) with safe alternatives (e.g., json).
9. Add concise security-focused comments where appropriate.
10. Final code must be syntactically valid and importable on Python 3.10 without NameError/ImportError.
11. Do NOT introduce external authentication frameworks or globals (e.g., current_user, flask_login) unless already present in the source. If an auth/authorization check is needed, implement minimal in-file helpers like:
    - is_authenticated(request) -> bool
    - is_admin(request) -> bool
    Define and use these helpers within the file using simple, safe placeholders (e.g., environment flags or request headers) without adding new dependencies.

OUTPUT RULES:
- Return ONLY the complete fixed code. No explanations, no markdown fences, no XML-like tags, no prose.
"""

        return prompt
    
    async def remediate_code(self, vulnerable_code: str, issues: List[SonarIssue], file_extension: str = None) -> Optional[str]:
        """
        Use Groq AI to remediate security vulnerabilities
        
        Args:
            vulnerable_code: The vulnerable source code
            issues: List of SonarQube issues
            file_extension: File extension to help with language detection
            
        Returns:
            Secure code or None if remediation failed
        """
        if not issues:
            logger.warning("No issues provided for remediation")
            return vulnerable_code
            
        prompt = self._create_remediation_prompt(vulnerable_code, issues, file_extension)
        
        for attempt in range(self.max_retries):
            try:
                logger.info(f"Attempting remediation (attempt {attempt + 1}/{self.max_retries})")
                
                chat_completion = self.client.chat.completions.create(
                    messages=[
                        {
                            "role": "system", 
                            "content": "You are a security expert. Return only runnable fixed code for a single file. Include all necessary imports and definitions. Do not introduce undefined names or external auth globals (e.g., current_user). If auth checks are needed, define minimal is_authenticated/is_admin helpers inside the file. Remove unused code. No markdown or explanations."
                        },
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    model=self.model,
                    temperature=0.1,  # Low temperature for consistent security fixes
                    max_tokens=8000,  # Increased for larger files
                    top_p=0.9
                )
                
                raw_output = chat_completion.choices[0].message.content
                
                # Extract clean code using enhanced extractor
                extractor = CodeExtractor(file_extension)
                secure_code = extractor.extract_clean_code(raw_output)
                
                # Basic validation of the response
                if self._validate_remediated_code(secure_code, vulnerable_code):
                    logger.info("Code remediation successful")
                    return secure_code
                else:
                    logger.warning(f"Invalid remediated code on attempt {attempt + 1}")
                    
            except Exception as e:
                logger.error(f"Remediation attempt {attempt + 1} failed: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))
                    
        logger.error("All remediation attempts failed")
        return None
    
    def _validate_remediated_code(self, secure_code: str, original_code: str) -> bool:
        """Enhanced validation of remediated code"""
        if not secure_code or len(secure_code.strip()) < 10:
            logger.warning("Remediated code is too short or empty")
            return False
        
        # Check if it's not just the same code
        if secure_code.strip() == original_code.strip():
            logger.warning("Remediated code is identical to original")
        
        # Check for common LLM artifacts that shouldn't be in code
        artifacts = ['<think>', '</think>', '```', 'here\'s the', 'here is the', 'the fixed code']
        for artifact in artifacts:
            if artifact.lower() in secure_code.lower():
                logger.warning(f"Found LLM artifact in code: {artifact}")
                return False
        
        # Basic structure validation - should look like code
        lines = secure_code.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        if len(non_empty_lines) == 0:
            return False
        
        # At least some lines should look like code (basic heuristic)
        code_like_lines = 0
        for line in non_empty_lines:
            if any(char in line for char in '(){}[];='):
                code_like_lines += 1
        
        if code_like_lines / len(non_empty_lines) < 0.3:  # At least 30% should look like code
            logger.warning("Remediated content doesn't appear to be code")
            return False
        
        return True
    
    def calculate_confidence_score(self, original_issues: List[SonarIssue], 
                                 remediated_code: str) -> float:
        """
        Calculate confidence score based on issue complexity and code changes
        """
        if not original_issues:
            return 0.0
            
        # Base confidence
        confidence = 0.8
        
        # Adjust based on issue severity
        critical_issues = sum(1 for issue in original_issues if issue.severity == 'CRITICAL')
        major_issues = sum(1 for issue in original_issues if issue.severity == 'MAJOR')
        minor_issues = sum(1 for issue in original_issues if issue.severity == 'MINOR')
        
        # Reduce confidence for critical issues
        confidence -= (critical_issues * 0.15)
        confidence -= (major_issues * 0.08)
        confidence -= (minor_issues * 0.03)
        
        # Boost confidence if code appears well-structured
        if remediated_code and len(remediated_code.strip()) > 50:
            confidence += 0.1
        
        # Ensure confidence is between 0 and 1
        return max(0.0, min(1.0, confidence))

class SecurityRemediationPipeline:
    """Main pipeline orchestrator for security remediation"""
    
    def __init__(self, groq_api_key: str, model: str = modelname):
        """
        Initialize the remediation pipeline
        
        Args:
            groq_api_key: Groq API key
            model: AI model to use
        """
        self.remediator = GroqSecurityRemediator(groq_api_key, model)
        self.parser = SonarQubeIssueParser()
        
    async def process_vulnerability(self, vulnerable_file_path: str, 
                                  sonar_json_path: str, 
                                  output_path: Optional[str] = None) -> RemediationResult:
        """
        Process a vulnerable file with SonarQube issues
        
        Args:
            vulnerable_file_path: Path to the vulnerable source file
            sonar_json_path: Path to SonarQube issues JSON
            output_path: Optional output path for secure file
            
        Returns:
            RemediationResult with details of the remediation
        """
        try:
            # Get file extension for language detection
            file_extension = Path(vulnerable_file_path).suffix
            
            # Read vulnerable code
            with open(vulnerable_file_path, 'r', encoding='utf-8') as f:
                vulnerable_code = f.read()
            
            # Read SonarQube issues
            with open(sonar_json_path, 'r', encoding='utf-8') as f:
                sonar_json = json.load(f)
            
            # Parse issues
            issues = self.parser.parse_issues(sonar_json)
            logger.info(f"Parsed {len(issues)} security issues for {file_extension} file")
            
            # Remediate code
            secure_code = await self.remediator.remediate_code(
                vulnerable_code, issues, file_extension
            )

            if secure_code is None:
                raise Exception("Failed to remediate code")

            # Save secure code
            if output_path:
                output_dir = os.path.dirname(output_path)
                if output_dir:
                    os.makedirs(output_dir, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(secure_code)
                logger.info(f"Secure code saved to {output_path}")
            
            # Calculate confidence score
            confidence = self.remediator.calculate_confidence_score(issues, secure_code)
            
            # Create result
            result = RemediationResult(
                original_file=vulnerable_file_path,
                secure_file=secure_code,
                issues_fixed=[issue.rule for issue in issues],
                confidence_score=confidence,
                timestamp=datetime.now(),
                model_used=self.remediator.model
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing vulnerability: {e}")
            raise
    
    async def batch_process(self, file_pairs: List[Tuple[str, str]], 
                          output_dir: str = "remediated") -> List[RemediationResult]:
        """
        Process multiple vulnerable files in batch
        
        Args:
            file_pairs: List of (vulnerable_file_path, sonar_json_path) tuples
            output_dir: Directory to save remediated files
            
        Returns:
            List of RemediationResult objects
        """
        results = []
        
        for i, (vulnerable_file, sonar_json) in enumerate(file_pairs):
            try:
                logger.info(f"Processing file {i+1}/{len(file_pairs)}: {vulnerable_file}")
                
                # Generate output path
                file_path = Path(vulnerable_file)
                output_path = os.path.join(output_dir, f"{file_path.stem}_secure{file_path.suffix}")
                
                # Process the file
                result = await self.process_vulnerability(
                    vulnerable_file, sonar_json, output_path
                )
                results.append(result)
                
                # Add delay between requests to respect rate limits
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Failed to process {vulnerable_file}: {e}")
                continue
                
        return results

def generate_remediation_report(results: List[RemediationResult], 
                              output_file: str = "remediation_report.json"):
    """Generate a detailed remediation report"""
    report_data = {
        "remediation_summary": {
            "total_files_processed": len(results),
            "successful_remediations": len([r for r in results if r.secure_file]),
            "average_confidence": sum(r.confidence_score for r in results) / len(results) if results else 0,
            "timestamp": datetime.now().isoformat()
        },
        "remediation_details": []
    }
    
    for result in results:
        report_data["remediation_details"].append({
            "original_file": result.original_file,
            "issues_fixed": result.issues_fixed,
            "confidence_score": result.confidence_score,
            "model_used": result.model_used,
            "timestamp": result.timestamp.isoformat(),
            "success": bool(result.secure_file)
        })
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2)
    
    logger.info(f"Remediation report saved to {output_file}")

# Example usage and CLI interface
async def main():
    """Example usage of the remediation pipeline"""
    
    # Configuration
    GROQ_API_KEY = os.getenv('GROQ_API_KEY')
    if not GROQ_API_KEY:
        raise ValueError("GROQ_API_KEY environment variable is required")
    
    # Initialize pipeline
    pipeline = SecurityRemediationPipeline(GROQ_API_KEY)
    
    # Example single file processing
    try:
        result = await pipeline.process_vulnerability(
            vulnerable_file_path="vulnerable_code.py",
            sonar_json_path="sonar_issues.json",
            output_path="secure_code.py"
        )
        
        logger.info(f"Remediation completed with confidence: {result.confidence_score}")
        logger.info(f"Issues fixed: {result.issues_fixed}")
        
    except Exception as e:
        logger.error(f"Remediation failed: {e}")

if __name__ == "__main__":
    import sys
    import os
    import asyncio
    import argparse
    from pathlib import Path

    parser = argparse.ArgumentParser(description="AI Security Remediation - Single File Mode")
    parser.add_argument("--src", default="vulnerable_file.py", help="Path to vulnerable source file")
    parser.add_argument("--sonar", default="output.json", help="Path to SonarQube issues JSON file")
    parser.add_argument("--out", default=None, help="Path to write the remediated file (default: <src>_secure.<ext>)")
    args = parser.parse_args()

    groq_api_key = os.getenv("GROQ_API_KEY")
    if not groq_api_key:
        print("Error: GROQ_API_KEY environment variable is required")
        sys.exit(1)

    src_path = args.src
    sonar_path = args.sonar
    if not os.path.exists(src_path):
        print(f"❌ Source file not found: {src_path}")
        sys.exit(1)
    if not os.path.exists(sonar_path):
        print(f"❌ Sonar issues file not found: {sonar_path}")
        sys.exit(1)

    src_path_obj = Path(src_path)
    default_out = str(src_path_obj.with_name(f"{src_path_obj.stem}_secure{src_path_obj.suffix}"))
    output_path = args.out or default_out

    async def run_single():
        pipeline = SecurityRemediationPipeline(groq_api_key)
        try:
            result = await pipeline.process_vulnerability(
                vulnerable_file_path=src_path,
                sonar_json_path=sonar_path,
                output_path=output_path
            )
            print(f"✅ Remediated: {src_path} -> {output_path} (Confidence: {result.confidence_score:.2f})")
        except Exception as e:
            print(f"❌ Remediation failed: {e}")
            sys.exit(1)

    asyncio.run(run_single())
