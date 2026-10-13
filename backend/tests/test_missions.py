import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.cloudscan import apply_fix, scan_cloud, world_admin
from backend.main import app
from backend.missions import collect_files, get, run_mission, save


class MissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"CLOUDGUARD_DATA_DIR": self.temp.name})
        self.env.start()
        self.client = TestClient(app)
        self.files, _ = collect_files(Path(__file__).resolve().parents[1] / "demo")

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def mission(self, files=None, planner="policy"):
        m = {"id": "test-mission", "created_at": "2026-01-01", "events": [], "planner": planner, "source": "demo", "repository": "fixture"}
        save(m)
        run_mission(m, self.files if files is None else files)
        return get(m["id"])

    def test_demo_resolves_three_findings_and_keeps_iam_blocked(self):
        m = self.mission()
        self.assertEqual(m["status"], "awaiting_approval")
        self.assertEqual(m["before"]["total"], 4)
        self.assertEqual(len(m["verification"]["resolved_ids"]), 3)
        self.assertEqual(m["after"]["total"], 1)
        self.assertEqual(m["after"]["gate"], "BLOCKED")
        self.assertIn('"FromPort": 443', m["patch"])
        self.assertEqual(m["before"]["risk_points"], 93)
        self.assertEqual(m["after"]["risk_points"], 25)

    def test_approval_bound_to_patch_hash_and_export_is_gated(self):
        m = self.mission()
        self.assertEqual(self.client.get('/missions/test-mission/patch').status_code, 409)
        self.assertEqual(self.client.post('/missions/test-mission/approve', json={"patch_sha256": "0" * 64}).status_code, 409)
        response = self.client.post('/missions/test-mission/approve', json={"patch_sha256": m["patch_sha256"]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "approved")
        self.assertEqual(self.client.get('/missions/test-mission/patch').text, m["patch"])
        self.assertNotIn('patch', self.client.get('/missions/test-mission/report').json())
        # Repeated approvals are idempotent.
        self.assertEqual(self.client.post('/missions/test-mission/approve', json={"patch_sha256": m["patch_sha256"]}).status_code, 200)

    def test_world_ingress_covers_ipv6_and_all_protocols(self):
        self.assertTrue(world_admin({"CidrIpv6": "::/0", "IpProtocol": "-1"}))
        self.assertTrue(world_admin({"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535}))
        self.assertFalse(world_admin({"CidrIp": "10.0.0.0/8", "IpProtocol": "-1"}))
        self.assertFalse(world_admin({"CidrIp": "0.0.0.0/0", "IpProtocol": "tcp", "FromPort": 443, "ToPort": 443}))

    def test_yaml_intrinsics_are_scanned_but_not_rewritten(self):
        result = scan_cloud({"stack.yml": "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !Sub '${AWS::AccountId}-test'\n"})
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(all(not f["fixable"] for f in result["findings"]))

    def test_parse_failure_and_empty_scan_never_pass(self):
        for files in ({"bad.json": '{"Resources": {'}, {}):
            m = self.mission(files)
            self.assertEqual(m["status"], "needs_review")
            self.assertEqual(m["after"]["gate"], "INCOMPLETE")
            self.assertFalse(m["verification"]["passed"])

    def test_symlinks_and_oversized_files_are_not_read(self):
        root = Path(self.temp.name)
        (root / "secret.py").symlink_to('/etc/passwd')
        (root / "large.py").write_text('x' * 200_001)
        (root / "linked-directory").symlink_to('/etc', target_is_directory=True)
        files, errors = collect_files(root)
        self.assertNotIn('secret.py', files)
        self.assertNotIn('large.py', files)
        self.assertEqual(len(errors), 3)

    def test_fixes_are_idempotent_and_preserve_https(self):
        items = scan_cloud(self.files)["findings"]
        files = self.files
        for item in items:
            if item["fixable"]:
                files = apply_fix(files, item)
                self.assertEqual(files, apply_fix(files, item))
        doc = json.loads(files['infra/template.json'])
        self.assertEqual(doc['Resources']['WebSecurityGroup']['Properties']['SecurityGroupIngress'][0]['FromPort'], 443)
        self.assertEqual(len(doc['Resources']['WebSecurityGroup']['Properties']['SecurityGroupIngress']), 1)
        self.assertEqual(len(scan_cloud(files)['findings']), 1)

    def test_agent_cannot_call_arbitrary_tools(self):
        with patch('backend.missions.AIPlanner') as planner:
            planner.return_value.next.return_value = ('execute_shell', {'command': 'echo unsafe'})
            m = self.mission(planner='ai')
        self.assertEqual(m['status'], 'failed')
        self.assertNotIn('patch', m)

    def test_agent_cannot_stage_without_inspection(self):
        item = next(f for f in scan_cloud(self.files)['findings'] if f['fixable'])
        with patch('backend.missions.AIPlanner') as planner:
            planner.return_value.next.return_value = ('stage_fix', {'finding_id': item['id']})
            m = self.mission(planner='ai')
        self.assertEqual(m['status'], 'failed')

    def test_model_tool_sequence_runs_same_verified_workflow(self):
        items = [f for f in scan_cloud(self.files)['findings'] if f['fixable']]
        calls = [(tool, {'finding_id': f['id']}) for f in items for tool in ('inspect_finding', 'stage_fix')]
        calls.append(('verify_patch', {}))
        with patch('backend.missions.AIPlanner') as planner:
            planner.return_value.next.side_effect = calls
            m = self.mission(planner='ai')
            self.assertEqual(planner.return_value.observe.call_count, 6)
        self.assertEqual(m['status'], 'awaiting_approval')
        self.assertEqual(len(m['verification']['resolved_ids']), 3)

    def test_dependency_scanner_error_blocks_legacy_security_gate(self):
        def clone(*args, **kwargs):
            destination = Path(args[0][-1])
            destination.mkdir()
            (destination / 'app.py').write_text('print("safe")\n')
            from subprocess import CompletedProcess
            return CompletedProcess(args[0], 0, '', '')
        audit = {'status': 'ERROR', 'findings': [], 'scanned_files': [], 'errors': [{'error': 'unavailable'}], 'message': 'Audit failed'}
        with patch('backend.main.subprocess.run', side_effect=clone), patch('backend.main.scan_python_dependencies', return_value=audit):
            response = self.client.post('/scan', json={'repo_url': 'https://github.com/example/repo'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['security_status'], 'ERROR')
        self.assertEqual(response.json()['deployment_readiness']['status'], 'NOT_READY')

    def test_credential_values_are_not_in_evidence_or_ai_context(self):
        files = {'app.py': 'password = "fixture-only-not-a-real-credential"\n'}
        m = self.mission(files)
        self.assertNotIn('fixture-only-not-a-real-credential', json.dumps(m))
        self.assertEqual(m['before']['counts']['HIGH'], 1)

    def test_bad_github_urls_rejected(self):
        for url in ('file:///etc', 'https://evil.example/repo', 'https://github.com/u/r?x=y', 'https://user:password@github.com/u/r'):
            self.assertEqual(self.client.post('/missions', json={'source': 'github', 'repo_url': url}).status_code, 422)

    def test_deployment_disabled_by_default(self):
        with patch.dict(os.environ, {'CLOUDGUARD_ENABLE_DEPLOYMENT': '0'}):
            self.assertEqual(self.client.post('/deployment/build', json={'repo_path': '/tmp'}).status_code, 403)


if __name__ == '__main__':
    unittest.main()
