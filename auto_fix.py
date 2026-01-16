import argparse
import base64
import json
import os
import re
import sys
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests

# Import your existing vulnerability detection and remediation systems
# from detector import VulnerabilityDetector
from remediation import SecurityRemediationPipeline

# Dynamically make detectors available from the detectors/ folder
_detectors_dir = os.path.join(os.path.dirname(__file__), "detectors")
if os.path.isdir(_detectors_dir) and _detectors_dir not in sys.path:
    sys.path.insert(0, _detectors_dir)

import os

# Ensure vulnerabilities folder exists in main branch (repo-clarity/public/vulnerabilities)
main_repo_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'repo-clarity', 'public', 'vulnerabilities')
os.makedirs(main_repo_dir, exist_ok=True)
try:
    import detectors.detector_python as detector_python
except Exception:
    detector_python = None

try:
    import detectors.detector_javascript as detector_javascript
except Exception:
    detector_javascript = None

try:
    import detectors.detector_go as detector_go
except Exception:
    detector_go = None

GITHUB_API = "https://api.github.com"


class GitHubClient:
    """Lightweight GitHub REST client for content and git operations."""

    def __init__(self, token: str, repo: str) -> None:
        if "/" not in repo:
            raise ValueError("github_repo must be in the form 'owner/repo'")
        self.token = token.strip()
        self.owner, self.repo = [p.strip() for p in repo.split("/", 1)]
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "auto-fix-script",
            }
        )

    def _url(self, path: str) -> str:
        return f"{GITHUB_API}{path}"

    def request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = self._url(path)
        response = self.session.request(method, url, timeout=60, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(
                f"GitHub API error {response.status_code} for {method} {path}: {response.text}"
            )
        return response

    def get_repo(self) -> Dict:
        return self.request("GET", f"/repos/{self.owner}/{self.repo}").json()

    def get_ref(self, ref: str) -> Dict:
        return self.request("GET", f"/repos/{self.owner}/{self.repo}/git/ref/{ref}").json()

    def get_commit(self, commit_sha: str) -> Dict:
        return self.request("GET", f"/repos/{self.owner}/{self.repo}/git/commits/{commit_sha}").json()

    def get_tree(self, tree_sha: str, recursive: bool = True) -> Dict:
        suffix = "?recursive=1" if recursive else ""
        return self.request(
            "GET", f"/repos/{self.owner}/{self.repo}/git/trees/{tree_sha}{suffix}"
        ).json()

    def get_blob_content(self, blob_sha: str) -> str:
        data = self.request(
            "GET", f"/repos/{self.owner}/{self.repo}/git/blobs/{blob_sha}"
        ).json()
        encoding = data.get("encoding")
        content = data.get("content", "")
        if encoding == "base64":
            return base64.b64decode(content).decode("utf-8", errors="replace")
        return content

    def create_tree(self, base_tree: str, entries: List[Dict]) -> str:
        payload = {"base_tree": base_tree, "tree": entries}
        data = self.request(
            "POST", f"/repos/{self.owner}/{self.repo}/git/trees", json=payload
        ).json()
        return data["sha"]

    def create_commit(self, message: str, tree_sha: str, parents: List[str]) -> str:
        payload = {"message": message, "tree": tree_sha, "parents": parents}
        data = self.request(
            "POST", f"/repos/{self.owner}/{self.repo}/git/commits", json=payload
        ).json()
        return data["sha"]

    def create_ref(self, ref: str, sha: str) -> None:
        payload = {"ref": f"refs/{ref}", "sha": sha}
        self.request("POST", f"/repos/{self.owner}/{self.repo}/git/refs", json=payload)

    def update_ref(self, ref: str, sha: str, force: bool = False) -> None:
        payload = {"sha": sha, "force": force}
        self.request("PATCH", f"/repos/{self.owner}/{self.repo}/git/refs/{ref}", json=payload)

    def create_pull_request(self, head: str, base: str, title: str, body: str) -> Dict:
        payload = {"head": head, "base": base, "title": title, "body": body}
        return self.request(
            "POST", f"/repos/{self.owner}/{self.repo}/pulls", json=payload
        ).json()


class VulnerabilityScanner:
    """Uses detectors in detectors/ to scan source files for vulnerabilities"""

    # Map extension to detector module object
    EXT_TO_MODULE = {
        ".py": detector_python,
        ".js": detector_javascript,
        ".go": detector_go,
    }

    def __init__(self):
        pass

    def _select_detector_module(self, file_path: str):
        _, ext = os.path.splitext(file_path.lower())
        return self.EXT_TO_MODULE.get(ext)

    def scan_file_content(self, file_path: str, content: str) -> List[Dict]:
        """Scan file content using the appropriate detector based on extension"""
        temp_file = f"temp_{os.path.basename(file_path)}"
        module = self._select_detector_module(file_path)
        if module is None:
            # Unknown/unsupported file type
            return []

        try:
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(content)

            vulnerabilities = []
            # Prefer a module-level scan_file(file_path) if available (simple and consistent)
            if hasattr(module, "scan_file"):
                try:
                    vulnerabilities = module.scan_file(temp_file)
                except Exception:
                    vulnerabilities = []

            # Fallbacks for detectors that expose a class
            if not vulnerabilities:
                # Standard expected class name
                detector_cls = getattr(module, "VulnerabilityDetector", None)
                if detector_cls is None:
                    # Try common alternative detector class names used in this repo
                    detector_cls = getattr(module, "JSVulnerabilityDetector", None) or getattr(module, "GoVulnerabilityDetector", None)

                if detector_cls is None:
                    # Nothing usable found
                    return []

                detector = detector_cls(temp_file)
                # detectors expose run_all_detections()
                vulnerabilities = detector.run_all_detections()

            converted_vulns = []
            for vuln in vulnerabilities:
                converted_vulns.append({
                    "line": vuln.get("line", 1),
                    "type": vuln.get("type", vuln.get("vuln_type", vuln.get("severity", "unknown"))),
                    "severity": vuln.get("severity", "MEDIUM").lower(),
                    "message": vuln.get("message", "Security vulnerability detected"),
                    "rule": vuln.get("rule", "unknown"),
                    "component": vuln.get("component", ""),
                    "project": vuln.get("project", ""),
                    "hash": vuln.get("hash", ""),
                    "textRange": vuln.get("textRange", {}),
                    "flows": vuln.get("flows", []),
                    "effort": vuln.get("effort", ""),
                    "debt": vuln.get("debt", ""),
                    "assignee": vuln.get("assignee", ""),
                    "author": vuln.get("author", ""),
                    "tags": vuln.get("tags", []),
                    "scope": vuln.get("scope", ""),
                    "quickFixAvailable": vuln.get("quickFixAvailable", False),
                    "messageFormattings": vuln.get("messageFormattings", []),
                })

            return converted_vulns

        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)


def generate_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_vulnerability_report(
    run_id: str,
    repo_full_name: str,
    per_file_issues: Dict[str, List[Dict]],
    per_file_fixes: Dict[str, Dict[str, int]],
) -> Dict:
    total_issues = sum(len(v) for v in per_file_issues.values())
    num_files_scanned = len(per_file_issues)

    def _has_numeric_change(fixes: Dict) -> bool:
        for value in fixes.values():
            if isinstance(value, (int, float)) and value > 0:
                return True
        return False

    num_files_changed = sum(1 for _, fixes in per_file_fixes.items() if _has_numeric_change(fixes))
    report = {
        "run_id": run_id,
        "repository": repo_full_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "num_files_scanned": num_files_scanned,
            "num_files_changed": num_files_changed,
            "total_issues": total_issues,
        },
        "files": [],
    }
    for path, issues in sorted(per_file_issues.items()):
        report["files"].append(
            {
                "path": path,
                "issues": issues,
                "fixes_applied": per_file_fixes.get(path, {}),
            }
        )
    return report


async def remediate_vulnerable_file(
    original_code: str,
    vulnerabilities: List[Dict],
    file_path: str,
    groq_api_key: str
) -> Tuple[str, Dict[str, int]]:
    """Use your existing remediation.py to fix vulnerabilities"""
    try:
        temp_vuln_file = f"temp_vulns_{os.path.basename(file_path)}.json"
        try:
            with open(temp_vuln_file, 'w', encoding='utf-8') as f:
                json.dump(vulnerabilities, f, indent=2)

            temp_src_file = f"temp_src_{os.path.basename(file_path)}"
            try:
                with open(temp_src_file, 'w', encoding='utf-8') as f:
                    f.write(original_code)

                pipeline = SecurityRemediationPipeline(groq_api_key)
                result = await pipeline.process_vulnerability(
                    vulnerable_file_path=temp_src_file,
                    sonar_json_path=temp_vuln_file,
                    output_path=None
                )

                fixes_applied = {
                    "ai_remediated": len(vulnerabilities),
                    "confidence_score": getattr(result, "confidence_score", None),
                    "model_used": getattr(result, "model_used", None)
                }

                return result.secure_file, fixes_applied

            finally:
                if os.path.exists(temp_src_file):
                    os.remove(temp_src_file)

        finally:
            if os.path.exists(temp_vuln_file):
                os.remove(temp_vuln_file)

    except Exception as e:
        print(f"Warning: AI remediation failed for {file_path}: {e}", file=sys.stderr)
        return original_code, {"ai_remediated": 0, "error": str(e)}


def collect_source_files_from_tree(tree: Dict) -> List[Dict]:
    entries: List[Dict] = []
    for node in tree.get("tree", []):
        if node.get("type") == "blob":
            path = node.get("path", "")
            if path.endswith((".py", ".js", ".go")):
                entries.append(node)
    return entries


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto-detect and fix Python, JavaScript and Go vulnerabilities using your existing systems, then open a PR"
    )
    parser.add_argument("--github_repo", help="owner/repo")
    parser.add_argument("--github_access_token", help="GitHub access token")
    parser.add_argument("--groq_api_key", help="Groq API key for AI remediation")
    args = parser.parse_args()

    github_repo = args.github_repo or os.environ.get("GITHUB_REPO")
    github_token = args.github_access_token or os.environ.get("GITHUB_TOKEN")
    groq_api_key = args.groq_api_key or os.environ.get("GROQ_API_KEY")

    if not github_repo:
        github_repo = input("Enter github_repo (owner/repo): ").strip()
    if not github_token:
        github_token = input("Enter github_access_token: ").strip()
    if not groq_api_key:
        groq_api_key = input("Enter Groq API key: ").strip()

    client = GitHubClient(github_token, github_repo)
    repo_info = client.get_repo()
    default_branch = repo_info.get("default_branch", "main")

    # Resolve tree for default branch
    ref_info = client.get_ref(f"heads/{default_branch}")
    head_commit_sha = ref_info["object"]["sha"]
    commit_info = client.get_commit(head_commit_sha)
    base_tree_sha = commit_info["tree"]["sha"]
    tree = client.get_tree(base_tree_sha, recursive=True)

    source_nodes = collect_source_files_from_tree(tree)
    scanner = VulnerabilityScanner()

    run_id = generate_run_id()
    per_file_issues: Dict[str, List[Dict]] = {}
    per_file_fixes: Dict[str, Dict[str, int]] = {}
    changed_files: Dict[str, str] = {}

    print(f"Scanning {len(source_nodes)} source files for vulnerabilities...")

    for i, node in enumerate(source_nodes, 1):
        path = node["path"]
        print(f"Processing {i}/{len(source_nodes)}: {path}")

        try:
            original_code = client.get_blob_content(node["sha"]) or ""
        except Exception as exc:
            print(f"Skipping {path}: failed to fetch blob content ({exc})", file=sys.stderr)
            continue

        issues = scanner.scan_file_content(path, original_code)
        per_file_issues[path] = issues

        if issues:
            print(f"  Found {len(issues)} vulnerabilities in {path}")
            fixed_code, fixes_applied = await remediate_vulnerable_file(
                original_code, issues, path, groq_api_key
            )
            per_file_fixes[path] = fixes_applied

            if fixed_code != original_code:
                changed_files[path] = fixed_code
                print(f"  Successfully remediated {path}")
        else:
            per_file_fixes[path] = {"ai_remediated": 0}

    report = build_vulnerability_report(
        run_id=run_id,
        repo_full_name=f"{client.owner}/{client.repo}",
        per_file_issues=per_file_issues,
        per_file_fixes=per_file_fixes,
    )

    report_path = "vulnerabilities/index.json"
    report_content = json.dumps(report, indent=2) + "\n"

    print(f"\nVulnerability scan complete!")
    print(f"Files scanned: {len(per_file_issues)}")
    print(f"Files with vulnerabilities: {len([f for f, issues in per_file_issues.items() if issues])}")
    print(f"Files remediated: {len(changed_files)}")
    print(f"Total vulnerabilities found: {sum(len(issues) for issues in per_file_issues.values())}")

    # Prepare new tree with all files from base tree plus changes
    tree_entries: List[Dict] = []

    # First, add all existing files from the base tree
    for node in tree.get("tree", []):
        if node.get("type") == "blob":
            path = node["path"]
            if path in changed_files:
                # Use the fixed content for changed files
                tree_entries.append({
                    "path": path,
                    "mode": node.get("mode", "100644"),
                    "type": "blob",
                    "content": changed_files[path]
                })
            else:
                # Keep existing files unchanged
                tree_entries.append({
                    "path": path,
                    "mode": node.get("mode", "100644"),
                    "type": "blob",
                    "sha": node["sha"]
                })

    # Add the vulnerabilities report
    tree_entries.append(
        {"path": report_path, "mode": "100644", "type": "blob", "content": report_content}
    )

    print(f"\nCreating commit with fixes...")
    new_tree_sha = client.create_tree(base_tree_sha, tree_entries)
    commit_message = f"Auto fix vulnerabilities using AI remediation (run {run_id})"
    new_commit_sha = client.create_commit(commit_message, new_tree_sha, [head_commit_sha])

    branch_name = f"auto-fix/run-{run_id}"
    client.create_ref(f"heads/{branch_name}", new_commit_sha)

    pr_base = "main"
    try:
        pr = client.create_pull_request(
            head=branch_name,
            base=pr_base,
            title=commit_message,
            body=(
                f"This PR applies AI-powered automated fixes for Python, JavaScript and Go vulnerabilities.\n\n"
                f"Run ID: {run_id}\n"
                f"Files scanned: {len(per_file_issues)}\n"
                f"Files with vulnerabilities: {len([f for f, issues in per_file_issues.items() if issues])}\n"
                f"Files remediated: {len(changed_files)}\n"
                f"Total vulnerabilities: {sum(len(issues) for issues in per_file_issues.values())}\n"
                f"Report: {report_path}\n\n"
                f"AI remediation powered by Groq API using your existing security pipeline."
            ),
        )
    except RuntimeError as exc:
        if "Unprocessable Entity" in str(exc) or "422" in str(exc):
            pr = client.create_pull_request(
                head=branch_name,
                base=default_branch,
                title=commit_message,
                body=(
                    f"This PR applies AI-powered automated fixes for Python, JavaScript and Go vulnerabilities.\n\n"
                    f"Run ID: {run_id}\n"
                    f"Files scanned: {len(per_file_issues)}\n"
                    f"Files with vulnerabilities: {len([f for f, issues in per_file_issues.items() if issues])}\n"
                    f"Files remediated: {len(changed_files)}\n"
                    f"Total vulnerabilities: {sum(len(issues) for issues in per_file_issues.values())}\n"
                    f"Report: {report_path}\n\n"
                    f"AI remediation powered by Groq API using your existing security pipeline."
                ),
            )
        else:
            raise

    pr_url = pr.get("html_url") or pr.get("url")
    print(f"\n✅ Created PR: {pr_url}")
    print(f"Branch: {branch_name}")
    print(f"Base branch: {pr_base}")


if __name__ == "__main__":
    asyncio.run(main())


