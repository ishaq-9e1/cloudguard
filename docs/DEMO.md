# CloudGuard: hackathon walkthrough

## Three-minute story

**0:00 — Problem.** “A scanner can list vulnerabilities. A deployment team still needs to decide what matters, make a change, and show that the change helped. CloudGuard connects those steps while preserving human review.”

**0:25 — Investigate.** Run the AWS demo mission. Show evidence for internet-facing administrative ingress and wildcard IAM permissions. Explain that the exposure paths are configuration-based scenarios, not a claim that an attacker has compromised the application.

**1:00 — Act.** Open Remediation. Show that HTTPS remains permitted while public administrative ingress is removed. Show S3 public-access controls being enabled. Explain the operational tradeoffs before approving.

**1:40 — Verify.** Show three resolved findings, no introduced findings, and 93 → 25 static risk points. Point out that IAM stays blocked because least privilege needs application context. The system refuses to invent an IAM policy or claim full readiness.

**2:15 — Review and evidence.** Approve the reviewed patch, export it, and show the tool timeline and source hash. No cloud resources or original source files have been modified.

**2:45 — Agent distinction.** With a configured provider key, the AI chooses tools and observes results within a constrained executor. Without a key, explicitly present the policy mode as a deterministic fallback. Do not describe the policy demo as a live LLM run.

## Applying an exported patch

Use a clean review branch of the scanned repository at the recorded commit. Review the full diff, then run `git apply --check <downloaded.patch>` followed by `git apply <downloaded.patch>`. Run CloudFormation template validation and application tests. Send the change through normal review before deployment. The included demo patch applies to the **demo fixture root**, not the CloudGuard repository root.

## Resume wording

“Built CloudGuard, a FastAPI/React cloud-security workbench with AWS CloudFormation checks, constrained AI tool orchestration, isolated patch verification, SQLite audit history, and hash-bound human approval.”

“Demonstrated a reproducible AWS fixture with 3 of 4 findings remediated and a 73% reduction in a documented static risk heuristic, while retaining an unresolved IAM security gate.”

Only claim live model validation after running with your own provider key. Only claim deployment integration or production security after implementing and testing those capabilities. Avoid claims of novel vulnerability detection, certification, or measured attack prevention.

## Next useful improvements

1. Validate candidates with CloudFormation tooling and an isolated AWS test account.
2. Add read-only AWS inventory and explicit resource relationships to replace conditional paths with account-specific evidence.
3. Add authenticated GitHub App pull-request creation, with review required before merge.
4. Add a fixture corpus and precision/recall evaluation for detection rules.
