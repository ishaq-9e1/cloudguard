"""Evidence-based CloudFormation checks. No templates or repository code are executed."""
import copy
import hashlib
import json
import re
from pathlib import Path

import yaml

WEIGHTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3}
PUBLIC_BLOCK = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")


class TemplateLoader(yaml.SafeLoader):
    pass


def intrinsic(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag if tag in {"Ref", "Condition"} else "Fn::" + tag: value}


TemplateLoader.add_multi_constructor("!", intrinsic)


def finding(rule, file, resource, severity, title, evidence, recommendation, fixable=False, line=None):
    identity = f"{rule}:{file}:{resource}:{line or ''}"
    return {"id": hashlib.sha256(identity.encode()).hexdigest()[:16], "rule": rule,
            "file": file, "resource": resource, "severity": severity, "title": title,
            "evidence": evidence, "recommendation": recommendation, "fixable": fixable,
            "line": line, "weight": WEIGHTS[severity]}


def world_admin(rule):
    if not isinstance(rule, dict):
        return False
    if rule.get("CidrIp") != "0.0.0.0/0" and rule.get("CidrIpv6") != "::/0":
        return False
    if str(rule.get("IpProtocol")) == "-1":
        return True
    if str(rule.get("IpProtocol")).lower() not in {"tcp", "6"}:
        return False
    try:
        return any(int(rule["FromPort"]) <= p <= int(rule["ToPort"]) for p in (22, 3389))
    except (ValueError, TypeError, KeyError):
        return False


def load_template(text, suffix):
    if suffix == ".json":
        return json.loads(text)
    # Reject aliases: avoid recursive structures and expansion attacks in untrusted YAML.
    for token in yaml.scan(text):
        if isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)):
            raise ValueError("YAML anchors/aliases require manual review")
    return yaml.load(text, Loader=TemplateLoader)


def scan_cloud(files):
    findings, errors, templates, resources = [], [], [], []
    for name, text in sorted(files.items()):
        suffix = Path(name).suffix.lower()
        if suffix not in {".json", ".yaml", ".yml"}:
            continue
        if not re.search(r'["\']?Resources["\']?\s*:', text):
            continue
        try:
            doc = load_template(text, suffix)
            if not isinstance(doc, dict) or not isinstance(doc.get("Resources"), dict):
                raise ValueError("Resources must be an object")
            templates.append(name)
            for key, obj in doc["Resources"].items():
                if not isinstance(obj, dict) or not isinstance(obj.get("Properties", {}), dict):
                    raise ValueError("Invalid resource shape")
                kind, props = obj.get("Type", ""), obj.get("Properties", {})
                resources.append({"file": name, "id": key, "type": kind})
                # Patches are deliberately limited to literal JSON resources.
                fixable = suffix == ".json" and "Condition" not in obj
                if kind == "AWS::EC2::SecurityGroup":
                    ingress = props.get("SecurityGroupIngress", [])
                    if not isinstance(ingress, list):
                        raise ValueError("Dynamic ingress requires manual review")
                    if any(world_admin(r) for r in ingress):
                        findings.append(finding("CG-AWS-001", name, key, "CRITICAL",
                            "Administrative ports exposed to the internet",
                            "An ingress rule allows SSH, RDP, or all protocols from a world CIDR.",
                            "Remove world-access administrative ingress. Add an approved private CIDR or use Session Manager.", fixable))
                if kind == "AWS::S3::Bucket":
                    block = props.get("PublicAccessBlockConfiguration", {})
                    if not isinstance(block, dict) or not all(block.get(k) is True for k in PUBLIC_BLOCK):
                        findings.append(finding("CG-AWS-002", name, key, "HIGH",
                            "Bucket public-access guardrails are incomplete",
                            "All four bucket-level public-access controls are not explicitly true. This does not prove data is public.",
                            "Enable all four S3 Block Public Access controls; review public website requirements first.", fixable))
                    if "BucketEncryption" not in props:
                        findings.append(finding("CG-AWS-003", name, key, "LOW",
                            "Encryption intent is not declared in infrastructure code",
                            "BucketEncryption is absent. S3 encrypts new objects by default; explicit policy prevents configuration ambiguity.",
                            "Declare server-side AES256 encryption or an organization-approved KMS key.", fixable))
                if kind in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}:
                    policies = props.get("Policies", [])
                    if not isinstance(policies, list):
                        raise ValueError("Dynamic IAM policies require manual review")
                    documents = [p.get("PolicyDocument", {}) for p in policies if isinstance(p, dict)]
                    documents.append(props.get("PolicyDocument", {}))
                    for policy in documents:
                        statements = policy.get("Statement", []) if isinstance(policy, dict) else []
                        if isinstance(statements, dict):
                            statements = [statements]
                        for st in statements:
                            if not isinstance(st, dict) or st.get("Effect") != "Allow":
                                continue
                            actions, targets = st.get("Action", []), st.get("Resource", [])
                            actions = [actions] if isinstance(actions, str) else actions
                            targets = [targets] if isinstance(targets, str) else targets
                            if isinstance(actions, list) and isinstance(targets, list) and "*" in targets and any(isinstance(a, str) and "*" in a for a in actions):
                                findings.append(finding("CG-AWS-004", name, key, "HIGH",
                                    "Wildcard permissions increase the blast radius",
                                    "An Allow statement combines wildcard actions with Resource '*'. Conditions and organization policies are not evaluated.",
                                    "Derive required actions from usage, scope resource ARNs, and test least-privilege access. Human review required."))
                                break
        except (ValueError, TypeError, yaml.YAMLError, RecursionError, AttributeError) as exc:
            errors.append({"file": name, "message": "Template could not be fully analyzed: " + type(exc).__name__})
    return {"findings": findings, "errors": errors, "templates": templates, "resources": resources}


def apply_fix(files, item):
    """Allowlisted transformations only; the model cannot supply arbitrary patches."""
    if not item["fixable"]:
        raise ValueError("This finding needs manual remediation")
    updated = copy.deepcopy(files)
    doc = json.loads(updated[item["file"]])
    props = doc["Resources"][item["resource"]].setdefault("Properties", {})
    if item["rule"] == "CG-AWS-001":
        props["SecurityGroupIngress"] = [r for r in props.get("SecurityGroupIngress", []) if not world_admin(r)]
    elif item["rule"] == "CG-AWS-002":
        props["PublicAccessBlockConfiguration"] = {k: True for k in PUBLIC_BLOCK}
    elif item["rule"] == "CG-AWS-003":
        props["BucketEncryption"] = {"ServerSideEncryptionConfiguration": [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
    else:
        raise ValueError("No approved transformation exists")
    updated[item["file"]] = json.dumps(doc, indent=2) + "\n"
    return updated


def summary(findings, errors):
    counts = {level: sum(f["severity"] == level for f in findings) for level in WEIGHTS}
    return {"counts": counts, "total": len(findings), "risk_points": sum(f["weight"] for f in findings),
            "gate": "INCOMPLETE" if errors else "BLOCKED" if counts["CRITICAL"] or counts["HIGH"] else "REVIEW" if findings else "CLEAR"}
