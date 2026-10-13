from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import subprocess
import shutil
import os
import re
import json
import sys
import stat

from backend.deployment import router as deployment_router
from backend.missions import router as missions_router


def _force_remove_readonly(func, path, exc_info=None):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass


# ============================================================
# CLOUDGAURD APPLICATION
# ============================================================

app = FastAPI(
    title="CLOUDGAURD API",
    description="Secure code scanning and cloud deployment platform",
    version="1.0"
)


# ============================================================
# CORS
# ============================================================

cors_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
]
env_origins = os.getenv("ALLOWED_ORIGINS")
if env_origins:
    cors_origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DEPLOYMENT ROUTER
# ============================================================

app.include_router(deployment_router)
app.include_router(missions_router)


# ============================================================
# REQUEST MODEL
# ============================================================

class ScanRequest(BaseModel):
    repo_url: str


# ============================================================
# PROJECT TYPE DETECTION
# ============================================================

def detect_project_type(repo_path):

    detected = set()

    ignored_dirs = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__"
    }

    for root, dirs, files in os.walk(repo_path):

        dirs[:] = [
            d for d in dirs
            if d not in ignored_dirs
        ]

        file_set = set(files)

        # -------------------------
        # Python
        # -------------------------

        if "requirements.txt" in file_set:
            detected.add("Python")

        if "pyproject.toml" in file_set:
            detected.add("Python")

        if "Pipfile" in file_set:
            detected.add("Python")

        if any(file.endswith(".py") for file in files):
            detected.add("Python")

        # -------------------------
        # Node / JavaScript
        # -------------------------

        if "package.json" in file_set:
            detected.add("Node.js / JavaScript")

        if any(file.endswith(".js") for file in files):
            detected.add("JavaScript")

        # -------------------------
        # Java
        # -------------------------

        if "pom.xml" in file_set:
            detected.add("Java Maven")

        if (
            "build.gradle" in file_set
            or "build.gradle.kts" in file_set
        ):
            detected.add("Java Gradle")

        # -------------------------
        # PHP
        # -------------------------

        if "composer.json" in file_set:
            detected.add("PHP")

        if any(file.endswith(".php") for file in files):
            detected.add("PHP")

        # -------------------------
        # .NET / C#
        # -------------------------

        if any(file.endswith(".csproj") for file in files):
            detected.add(".NET / C#")

        if any(file.endswith(".cs") for file in files):
            detected.add(".NET / C#")

        # -------------------------
        # Go
        # -------------------------

        if "go.mod" in file_set:
            detected.add("Go")

        if any(file.endswith(".go") for file in files):
            detected.add("Go")

        # -------------------------
        # Rust
        # -------------------------

        if "Cargo.toml" in file_set:
            detected.add("Rust")

        if any(file.endswith(".rs") for file in files):
            detected.add("Rust")

        # -------------------------
        # Docker
        # -------------------------

        if (
            "Dockerfile" in file_set
            or any(
                file.lower().endswith(".dockerfile")
                for file in files
            )
        ):
            detected.add("Docker")

        # -------------------------
        # Frontend
        # -------------------------

        if any(file.endswith(".html") for file in files):
            detected.add("HTML")

        if any(file.endswith(".css") for file in files):
            detected.add("CSS")

        # -------------------------
        # C
        # -------------------------

        if any(
            file.endswith((".c", ".h"))
            for file in files
        ):
            detected.add("C")

        # -------------------------
        # C++
        # -------------------------

        if any(
            file.endswith(
                (".cpp", ".cc", ".cxx", ".hpp", ".hh")
            )
            for file in files
        ):
            detected.add("C++")

    if not detected:
        detected.add("Unknown")

    return sorted(detected)


# ============================================================
# SECRET SCANNING
# ============================================================

def scan_for_secrets(repo_path):

    findings = []

    allowed_extensions = {
        ".py",
        ".js",
        ".ts",
        ".json",
        ".html",
        ".css",
        ".env",
        ".txt",
        ".yaml",
        ".yml",
        ".ini",
        ".cfg",
        ".conf",
        ".xml",
        ".properties"
    }

    secret_patterns = [

        {
            "type": "Possible Password",
            "pattern": (
                r'(?i)\bpassword\b\s*[:=]\s*["\'][^"\']+["\']'
            ),
            "severity": "HIGH",
            "explanation": (
                "A password appears to be hard-coded directly "
                "in the source code."
            ),
            "recommendation": (
                "Move the password to an environment variable "
                "or secret manager."
            )
        },

        {
            "type": "Possible API Key",
            "pattern": (
                r'(?i)\bapi[_-]?key\b\s*[:=]\s*["\'][^"\']+["\']'
            ),
            "severity": "HIGH",
            "explanation": (
                "An API key appears to be hard-coded directly "
                "in the source code."
            ),
            "recommendation": (
                "Move the API key to an environment variable "
                "or secret manager."
            )
        },

        {
            "type": "Possible Secret",
            "pattern": (
                r'(?i)\bsecret(?:_key)?\b\s*[:=]\s*["\'][^"\']+["\']'
            ),
            "severity": "HIGH",
            "explanation": (
                "A secret value appears to be hard-coded directly "
                "in the source code."
            ),
            "recommendation": (
                "Move the secret to an environment variable "
                "or secret manager."
            )
        },

        {
            "type": "Possible Token",
            "pattern": (
                r'(?i)\b(?:access_)?token\b\s*[:=]\s*["\'][^"\']+["\']'
            ),
            "severity": "HIGH",
            "explanation": (
                "A token appears to be hard-coded directly "
                "in the source code."
            ),
            "recommendation": (
                "Move the token to an environment variable "
                "or secret manager."
            )
        },

        {
            "type": "Private Key",
            "pattern": (
                r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
            ),
            "severity": "CRITICAL",
            "explanation": (
                "A private cryptographic key was found inside "
                "the repository."
            ),
            "recommendation": (
                "Remove the private key from source control "
                "and rotate it immediately."
            )
        }
    ]

    ignored_dirs = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__"
    }

    for root, dirs, files in os.walk(repo_path):

        dirs[:] = [
            d for d in dirs
            if d not in ignored_dirs
        ]

        for file in files:

            file_path = os.path.join(root, file)

            _, extension = os.path.splitext(file)

            should_scan = (
                extension.lower() in allowed_extensions
                or file == ".env"
            )

            if not should_scan:
                continue

            try:

                with open(
                    file_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:

                    for line_number, line in enumerate(
                        f,
                        start=1
                    ):

                        for rule in secret_patterns:

                            if re.search(
                                rule["pattern"],
                                line
                            ):

                                relative_path = os.path.relpath(
                                    file_path,
                                    repo_path
                                )

                                findings.append({
                                    "type": rule["type"],
                                    "file": relative_path,
                                    "line": line_number,
                                    "severity": rule["severity"],
                                    "explanation": rule["explanation"],
                                    "recommendation": rule["recommendation"]
                                })

            except Exception:
                continue

    return findings


# ============================================================
# STATIC CODE SECURITY SCANNING
# ============================================================

def scan_source_code(repo_path):

    findings = []

    security_rules = [

        {
            "type": "Dangerous eval() Usage",
            "pattern": r'\beval\s*\(',
            "severity": "HIGH",
            "explanation": (
                "eval() executes Python code dynamically. "
                "If attacker-controlled input reaches eval(), "
                "it can lead to arbitrary code execution."
            ),
            "recommendation": (
                "Avoid eval(). Parse and validate the input "
                "using a safer method."
            )
        },

        {
            "type": "Dangerous exec() Usage",
            "pattern": r'\bexec\s*\(',
            "severity": "HIGH",
            "explanation": (
                "exec() dynamically executes Python code "
                "and may allow arbitrary code execution."
            ),
            "recommendation": (
                "Avoid exec() when processing external "
                "or user-controlled input."
            )
        },

        {
            "type": "Operating System Command Execution",
            "pattern": r'\bos\.system\s*\(',
            "severity": "HIGH",
            "explanation": (
                "os.system() executes operating-system commands. "
                "Unsafe input may result in command injection."
            ),
            "recommendation": (
                "Avoid os.system(). Prefer subprocess with a list "
                "of arguments and validate all input."
            )
        },

        {
            "type": "Shell Command Execution",
            "pattern": r'shell\s*=\s*True',
            "severity": "HIGH",
            "explanation": (
                "Using shell=True can expose the application "
                "to command injection when untrusted data is used."
            ),
            "recommendation": (
                "Use shell=False and pass command arguments "
                "as a list whenever possible."
            )
        },

        {
            "type": "Unsafe Pickle Deserialization",
            "pattern": r'\bpickle\.(load|loads)\s*\(',
            "severity": "HIGH",
            "explanation": (
                "Python pickle can execute arbitrary code "
                "while deserializing malicious data."
            ),
            "recommendation": (
                "Do not deserialize untrusted pickle data. "
                "Use safer formats such as JSON where possible."
            )
        },

        {
            "type": "Flask Debug Mode Enabled",
            "pattern": r'\bdebug\s*=\s*True',
            "severity": "MEDIUM",
            "explanation": (
                "Debug mode can expose internal application "
                "details and must not be enabled in production."
            ),
            "recommendation": (
                "Disable debug mode before deploying the application."
            )
        },

        {
            "type": "Unsafe YAML Loading",
            "pattern": r'\byaml\.load\s*\(',
            "severity": "HIGH",
            "explanation": (
                "Unsafe YAML deserialization may allow execution "
                "of malicious Python objects."
            ),
            "recommendation": (
                "Use yaml.safe_load() instead of yaml.load() "
                "for untrusted YAML data."
            )
        }
    ]

    ignored_dirs = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__"
    }

    for root, dirs, files in os.walk(repo_path):

        dirs[:] = [
            d for d in dirs
            if d not in ignored_dirs
        ]

        for file in files:

            if not file.endswith(".py"):
                continue

            file_path = os.path.join(root, file)

            try:

                with open(
                    file_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:

                    for line_number, line in enumerate(
                        f,
                        start=1
                    ):

                        stripped_line = line.strip()

                        if stripped_line.startswith("#"):
                            continue

                        for rule in security_rules:

                            if re.search(
                                rule["pattern"],
                                line
                            ):

                                relative_path = os.path.relpath(
                                    file_path,
                                    repo_path
                                )

                                findings.append({
                                    "type": rule["type"],
                                    "file": relative_path,
                                    "line": line_number,
                                    "severity": rule["severity"],
                                    "explanation": rule["explanation"],
                                    "recommendation": rule["recommendation"]
                                })

            except Exception:
                continue

    return findings


# ============================================================
# PYTHON DEPENDENCY SCANNING
# ============================================================

def scan_python_dependencies(repo_path):

    findings = []
    scanned_files = []
    scan_errors = []
    requirements_files = []

    ignored_dirs = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__"
    }

    for root, dirs, files in os.walk(repo_path):

        dirs[:] = [
            d for d in dirs
            if d not in ignored_dirs
        ]

        for file in files:

            if file.lower() == "requirements.txt":

                requirements_files.append(
                    os.path.join(root, file)
                )

    if not requirements_files:

        return {
            "status": "SKIPPED",
            "message": (
                "No requirements.txt file found. "
                "Python dependency scan was skipped."
            ),
            "scanned_files": [],
            "findings": [],
            "errors": []
        }

    for requirements_file in requirements_files:

        relative_requirements = os.path.relpath(
            requirements_file,
            repo_path
        )

        scanned_files.append(relative_requirements)

        try:

            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip_audit",
                    "-r",
                    requirements_file,
                    "--disable-pip",
                    "--no-deps",
                    "--format",
                    "json",
                    "--progress-spinner",
                    "off"
                ],
                capture_output=True,
                text=True,
                timeout=180
            )

            if result.returncode not in (0, 1):

                scan_errors.append({
                    "file": relative_requirements,
                    "error": (
                        result.stderr.strip()
                        or "Dependency scanner failed."
                    )
                })

                continue

            if not result.stdout.strip():
                scan_errors.append({"file": relative_requirements, "error": "Dependency scanner returned no results."})
                continue

            try:

                audit_data = json.loads(
                    result.stdout
                )

            except json.JSONDecodeError:

                scan_errors.append({
                    "file": relative_requirements,
                    "error": (
                        "pip-audit returned invalid JSON output."
                    )
                })

                continue

            if isinstance(audit_data, dict):

                dependencies = audit_data.get(
                    "dependencies",
                    []
                )

            elif isinstance(audit_data, list):

                dependencies = audit_data

            else:

                dependencies = []

            for dependency in dependencies:

                package_name = dependency.get(
                    "name",
                    "Unknown"
                )

                package_version = dependency.get(
                    "version",
                    "Unknown"
                )

                vulnerabilities = (
                    dependency.get("vulns")
                    or dependency.get("vulnerabilities")
                    or []
                )

                for vulnerability in vulnerabilities:

                    vulnerability_id = (
                        vulnerability.get("id")
                        or vulnerability.get("vulnerability_id")
                        or "Unknown"
                    )

                    fix_versions = (
                        vulnerability.get("fix_versions")
                        or vulnerability.get("fix")
                        or []
                    )

                    description = (
                        vulnerability.get("description")
                        or vulnerability.get("details")
                        or "Known vulnerability detected."
                    )

                    recommendation = (
                        "Update the dependency to a secure version."
                    )

                    if fix_versions:

                        recommendation = (
                            "Upgrade "
                            + package_name
                            + " to one of the fixed versions: "
                            + ", ".join(
                                str(version)
                                for version in fix_versions
                            )
                        )

                    findings.append({
                        "type": "Vulnerable Dependency",
                        "package": package_name,
                        "installed_version": package_version,
                        "vulnerability_id": vulnerability_id,
                        "severity": "HIGH",
                        "dependency_file": relative_requirements,
                        "explanation": description,
                        "fix_versions": fix_versions,
                        "recommendation": recommendation
                    })

        except subprocess.TimeoutExpired:

            scan_errors.append({
                "file": relative_requirements,
                "error": "Dependency scan timed out."
            })

        except Exception as error:

            scan_errors.append({
                "file": relative_requirements,
                "error": str(error)
            })

    if findings:

        status = "FAILED"

    elif scan_errors:

        status = "ERROR"

    else:

        status = "PASSED"

    return {
        "status": status,
        "message": "Python dependency scanning completed.",
        "scanned_files": scanned_files,
        "findings": findings,
        "errors": scan_errors
    }


# ============================================================
# DOCKERFILE SECURITY SCANNING
# ============================================================

def scan_dockerfiles(repo_path):

    findings = []
    dockerfiles = []

    ignored_dirs = {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__"
    }

    for root, dirs, files in os.walk(repo_path):

        dirs[:] = [
            d for d in dirs
            if d not in ignored_dirs
        ]

        for file in files:

            if (
                file == "Dockerfile"
                or file.lower().endswith(".dockerfile")
            ):

                dockerfiles.append(
                    os.path.join(root, file)
                )

    if not dockerfiles:

        return {
            "status": "SKIPPED",
            "message": (
                "No Dockerfile found. "
                "Docker security scan was skipped."
            ),
            "scanned_files": [],
            "findings": []
        }

    for dockerfile_path in dockerfiles:

        relative_path = os.path.relpath(
            dockerfile_path,
            repo_path
        )

        try:

            with open(
                dockerfile_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                lines = f.readlines()

        except Exception:

            continue

        has_user_instruction = False
        last_user_value = None

        for line_number, raw_line in enumerate(
            lines,
            start=1
        ):

            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            # -------------------------
            # FROM latest
            # -------------------------

            if re.match(
                r'(?i)^FROM\s+\S+:latest(?:\s|$)',
                line
            ):

                findings.append({
                    "type": "Unpinned Docker Base Image",
                    "file": relative_path,
                    "line": line_number,
                    "severity": "MEDIUM",
                    "explanation": (
                        "The Dockerfile uses the 'latest' image tag. "
                        "The image can change unexpectedly between builds."
                    ),
                    "recommendation": (
                        "Pin the base image to a specific trusted "
                        "version or immutable digest."
                    )
                })

            # -------------------------
            # FROM without tag
            # -------------------------

            from_match = re.match(
                r'(?i)^FROM\s+([^\s]+)',
                line
            )

            if from_match:

                image = from_match.group(1)

                if (
                    ":" not in image
                    and "@" not in image
                    and image.lower() != "scratch"
                ):

                    findings.append({
                        "type": "Unpinned Docker Base Image",
                        "file": relative_path,
                        "line": line_number,
                        "severity": "MEDIUM",
                        "explanation": (
                            "The Docker base image has no explicit "
                            "version tag and may resolve to a "
                            "changing image."
                        ),
                        "recommendation": (
                            "Pin the base image to a specific "
                            "trusted version or immutable digest."
                        )
                    })

            # -------------------------
            # USER
            # -------------------------

            user_match = re.match(
                r'(?i)^USER\s+(.+)$',
                line
            )

            if user_match:

                has_user_instruction = True

                last_user_value = (
                    user_match.group(1).strip()
                )

                if last_user_value.lower() in {
                    "root",
                    "0"
                }:

                    findings.append({
                        "type": "Container Runs As Root",
                        "file": relative_path,
                        "line": line_number,
                        "severity": "HIGH",
                        "explanation": (
                            "The Dockerfile explicitly configures "
                            "the container to run as the root user."
                        ),
                        "recommendation": (
                            "Create and use a non-root user "
                            "for the application."
                        )
                    })

            # -------------------------
            # ADD URL
            # -------------------------

            if re.match(
                r'(?i)^ADD\s+https?://',
                line
            ):

                findings.append({
                    "type": "Remote File Added During Docker Build",
                    "file": relative_path,
                    "line": line_number,
                    "severity": "MEDIUM",
                    "explanation": (
                        "The Dockerfile downloads a remote file "
                        "using ADD. Remote content can change "
                        "and is harder to verify."
                    ),
                    "recommendation": (
                        "Download files explicitly and verify "
                        "their checksum before using them."
                    )
                })

            # -------------------------
            # ENV / ARG secrets
            # -------------------------

            if re.match(
                r'(?i)^(ENV|ARG)\s+.*\b'
                r'(password|passwd|secret|token|api[_-]?key)\b',
                line
            ):

                findings.append({
                    "type": "Possible Secret In Dockerfile",
                    "file": relative_path,
                    "line": line_number,
                    "severity": "HIGH",
                    "explanation": (
                        "A Docker ENV or ARG instruction appears "
                        "to contain a sensitive credential-like value."
                    ),
                    "recommendation": (
                        "Do not bake secrets into images. "
                        "Provide them securely at runtime using "
                        "environment variables or a secret manager."
                    )
                })

            # -------------------------
            # COPY . .
            # -------------------------

            if re.match(
                r'(?i)^COPY\s+\.\s+\.',
                line
            ):

                findings.append({
                    "type": "Broad Docker Build Context Copy",
                    "file": relative_path,
                    "line": line_number,
                    "severity": "LOW",
                    "explanation": (
                        "COPY . . copies the entire build context "
                        "into the image. Unnecessary or sensitive "
                        "files may be included."
                    ),
                    "recommendation": (
                        "Use a .dockerignore file and copy only "
                        "the files required by the application."
                    )
                })

        # -------------------------
        # No USER instruction
        # -------------------------

        if not has_user_instruction:

            findings.append({
                "type": "No Non-Root User Configured",
                "file": relative_path,
                "line": None,
                "severity": "MEDIUM",
                "explanation": (
                    "No USER instruction was found. Most images "
                    "run as root by default unless the base image "
                    "changes that behavior."
                ),
                "recommendation": (
                    "Create a dedicated non-root user and add "
                    "a USER instruction before the application starts."
                )
            })

        elif (
            last_user_value
            and last_user_value.lower() in {"root", "0"}
        ):

            pass

    status = "FAILED" if findings else "PASSED"

    return {
        "status": status,
        "message": "Dockerfile security scanning completed.",
        "scanned_files": [
            os.path.relpath(
                path,
                repo_path
            )
            for path in dockerfiles
        ],
        "findings": findings
    }


# ============================================================
# DEPLOYMENT READINESS CHECK
# ============================================================

def check_deployment_readiness(repo_path, security_status):
    checks = []
    blockers = []
    dockerfiles = []

    # 1. SECURITY GATE
    security_passed = security_status == "PASSED"
    checks.append({
        "check": "Security checks passed",
        "status": "PASSED" if security_passed else "FAILED",
        "message": (
            "Repository passed current CLOUDGAURD security checks."
            if security_passed else
            "Security findings must be resolved before deployment."
        )
    })

    if not security_passed:
        blockers.append(
            "Resolve security findings before deployment."
        )

    # 2. DISCOVER PROJECT FILES AND DOCKERFILES
    ignored_dirs = {
        ".git", "node_modules", "venv", ".venv",
        "__pycache__", "target", "build", "dist"
    }
    project_files = set()

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]

        for file in files:
            relative_path = os.path.normpath(
                os.path.relpath(os.path.join(root, file), repo_path)
            ).replace("\\", "/")
            project_files.add(relative_path)

            if file == "Dockerfile" or file.lower().endswith(".dockerfile"):
                dockerfiles.append(os.path.join(root, file))

    # Project manifests can be at repository root or in project submodules
    root_files = {
        path.split("/")[-1]
        for path in project_files
        if "/" not in path
    }

    # 3. CHECK DOCKERFILE
    dockerfile_checks_passed = False
    dockerfile_details = []

    for dockerfile_path in dockerfiles:
        relative_path = os.path.relpath(dockerfile_path, repo_path)
        try:
            with open(
                dockerfile_path, "r", encoding="utf-8", errors="ignore"
            ) as f:
                content = f.read()

            has_from = bool(re.search(
                r"(?im)^\s*FROM\s+\S+", content
            ))
            has_start_command = bool(re.search(
                r"(?im)^\s*(CMD|ENTRYPOINT)\s+", content
            ))

            dockerfile_details.append({
                "file": relative_path,
                "has_from": has_from,
                "has_start_command": has_start_command
            })

            if has_from and has_start_command:
                dockerfile_checks_passed = True

        except Exception as error:
            dockerfile_details.append({
                "file": relative_path,
                "has_from": False,
                "has_start_command": False,
                "error": str(error)
            })

    dockerfile_exists = bool(dockerfiles)
    checks.append({
        "check": "Dockerfile exists",
        "status": "PASSED" if dockerfile_exists else "SKIPPED",
        "message": (
            "Docker configuration found."
            if dockerfile_exists else
            "No Dockerfile found; checking alternative build methods."
        )
    })

    if dockerfile_exists:
        checks.append({
            "check": "Dockerfile basic instructions",
            "status": "PASSED" if dockerfile_checks_passed else "FAILED",
            "message": (
                "A Dockerfile contains FROM and CMD/ENTRYPOINT."
                if dockerfile_checks_passed else
                "No readable Dockerfile contains both FROM and "
                "CMD/ENTRYPOINT instructions."
            )
        })

    # 4. SELECT A DETECTED BUILD PATH
    # This detects a possible build path; it does not run the build.
    build_method = None

    has_docker = dockerfile_checks_passed
    # Maven projects can live at the repository root or in a nested module.
    # Normalize separators before checking so Windows paths are handled too.
    has_maven = any(
        path.replace("\\\\", "/").split("/")[-1].lower() == "pom.xml"
        for path in project_files
    )
    has_gradle = (
        bool({"build.gradle", "build.gradle.kts", "gradlew"} & root_files)
        or any(
            p.split("/")[-1] in {"build.gradle", "build.gradle.kts", "gradlew"}
            for p in project_files
        )
    )
    has_node = (
        bool({"package.json"} & root_files)
        or any(p.split("/")[-1] == "package.json" for p in project_files)
    )
    has_python = (
        bool({"requirements.txt", "pyproject.toml"} & root_files)
        or any(
            p.split("/")[-1] in {"requirements.txt", "pyproject.toml"}
            for p in project_files
        )
    )

    if has_docker:
        build_method = "docker"
    elif has_maven:
        build_method = "maven"
    elif has_gradle:
        build_method = "gradle"
    elif has_node:
        build_method = "node"
    elif has_python:
        build_method = "python"

    checks.append({
        "check": "Supported build configuration",
        "status": "PASSED" if build_method else "FAILED",
        "message": (
            f"Detected build method: {build_method}. A real build "
            "must still be run before deployment."
            if build_method else
            "No supported Docker, Maven, Gradle, Node.js, or Python "
            "build configuration was detected."
        )
    })

    if not build_method:
        blockers.append(
            "Add or configure a supported build method for this project."
        )

    # 5. FINAL STATUS
    ready = security_passed and build_method is not None

    return {
        "status": "READY" if ready else "NOT_READY",
        "message": (
            f"Security gate passed. Project is ready for the "
            f"{build_method} build step; build success is not yet verified."
            if ready else
            "Project is not ready for the build step. Review checks and blockers."
        ),
        "checks": checks,
        "dockerfile_details": dockerfile_details,
        "blockers": blockers,
        "build_method": build_method
    }


# ============================================================
# HOME ENDPOINT
# ============================================================

@app.get("/")
def home():

    return {
        "message": "CLOUDGAURD backend is running"
    }


# ============================================================
# HEALTH ENDPOINT
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "ok",
        "service": "CLOUDGAURD"
    }


# ============================================================
# SCAN ENDPOINT
# ============================================================

@app.post("/scan")
def scan_repository(request: ScanRequest):

    repo_url = request.repo_url.strip()

    # -------------------------
    # VALIDATE URL
    # -------------------------

    if not re.fullmatch(
        r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?/?",
        repo_url,
        flags=re.IGNORECASE,
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Please provide a valid public "
                "GitHub repository URL"
            )
        )

    # Isolate concurrent scans and never delete a previous user's checkout.
    import tempfile
    from pathlib import Path
    from backend.missions import collect_files
    repo_name = repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
    repositories_folder = Path(__file__).resolve().parents[1] / "repositories"
    repositories_folder.mkdir(exist_ok=True)
    destination = tempfile.mkdtemp(prefix="scan-", dir=repositories_folder)
    clone_destination = os.path.join(destination, "source")

    # ========================================================
    # MAIN SCANNING PIPELINE
    # ========================================================

    try:

        # ----------------------------------------------------
        # STEP 1 - CLONE REPOSITORY
        # ----------------------------------------------------

        result = subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                "--",
                repo_url,
                clone_destination
            ],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:

            raise HTTPException(
                status_code=400,
                detail=(
                    "Git clone failed. Check the GitHub URL and repository access."
                )
            )

        files, collection_errors = collect_files(Path(clone_destination))
        # Analyze bounded regular files, not checkout symlinks or hooks.
        shutil.rmtree(clone_destination)
        for name, content in files.items():
            target = Path(destination) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)

        # ----------------------------------------------------
        # STEP 2 - DETECT TECHNOLOGY
        # ----------------------------------------------------

        project_type = detect_project_type(
            destination
        )

        # ----------------------------------------------------
        # STEP 3 - SECRET SCANNING
        # ----------------------------------------------------

        secret_findings = scan_for_secrets(
            destination
        )

        # ----------------------------------------------------
        # STEP 4 - STATIC CODE SECURITY SCANNING
        # ----------------------------------------------------

        code_findings = scan_source_code(
            destination
        )

        # ----------------------------------------------------
        # STEP 5 - DEPENDENCY SCANNING
        # ----------------------------------------------------

        dependency_scan = scan_python_dependencies(
            destination
        )

        dependency_findings = (
            dependency_scan["findings"]
        )

        # ----------------------------------------------------
        # STEP 6 - DOCKERFILE SECURITY SCANNING
        # ----------------------------------------------------

        docker_scan = scan_dockerfiles(
            destination
        )

        docker_findings = (
            docker_scan["findings"]
        )

        # ----------------------------------------------------
        # CALCULATE FINDINGS
        # ----------------------------------------------------

        total_findings = (
            len(secret_findings)
            + len(code_findings)
            + len(dependency_findings)
            + len(docker_findings)
        )

        # ----------------------------------------------------
        # SECURITY STATUS
        # ----------------------------------------------------

        security_status = (
            "ERROR" if collection_errors or not files or dependency_scan["status"] == "ERROR"
            else "FAILED" if total_findings > 0
            else "PASSED"
        )

        # ----------------------------------------------------
        # STEP 7 - DEPLOYMENT READINESS
        # ----------------------------------------------------

        deployment_readiness = (
            check_deployment_readiness(
                destination,
                security_status
            )
        )

        # ----------------------------------------------------
        # FINAL RESPONSE
        # ----------------------------------------------------

        return {

            "repo_url": repo_url,

            "repository_name": repo_name,

            "clone_status": (
                "repository cloned successfully"
            ),

            "project_type": project_type,

            "security_status": security_status,

            "security_summary": {

                "total_findings": total_findings,

                "secret_findings": (
                    len(secret_findings)
                ),

                "code_findings": (
                    len(code_findings)
                ),

                "dependency_findings": (
                    len(dependency_findings)
                ),

                "docker_findings": (
                    len(docker_findings)
                )
            },

            "secret_findings": secret_findings,

            "code_findings": code_findings,

            "dependency_scan": {

                "status": dependency_scan["status"],

                "message": dependency_scan["message"],

                "scanned_files": (
                    dependency_scan["scanned_files"]
                ),

                "errors": dependency_scan["errors"]
            },

            "dependency_findings": dependency_findings,

            "docker_scan": {

                "status": docker_scan["status"],

                "message": docker_scan["message"],

                "scanned_files": (
                    docker_scan["scanned_files"]
                )
            },

            "docker_findings": docker_findings,

            "deployment_readiness": (
                deployment_readiness
            ),

            "saved_to": destination,
            "collection_errors": collection_errors
        }

    except subprocess.TimeoutExpired:

        raise HTTPException(
            status_code=408,
            detail=(
                "Repository cloning timed out after "
                "120 seconds."
            )
        )

    except HTTPException:

        # Preserve intentional HTTP errors.

        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "CLOUDGAURD scan failed: "
                + str(error)
            )
        )


# ============================================================
# END
# ============================================================