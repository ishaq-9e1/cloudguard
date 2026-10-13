import os
import tempfile
import unittest

from backend.main import check_deployment_readiness, detect_project_type


class ReadinessDetectionTests(unittest.TestCase):
    def test_nested_maven_project_is_detected(self):
        with tempfile.TemporaryDirectory() as repo:
            module = os.path.join(repo, "myproject")
            os.makedirs(module)
            with open(os.path.join(module, "pom.xml"), "w", encoding="utf-8") as f:
                f.write("<project></project>")

            result = check_deployment_readiness(repo, "PASSED")
            self.assertEqual(result["build_method"], "maven")
            self.assertEqual(result["status"], "READY")

    def test_valid_dockerfile_is_detected(self):
        with tempfile.TemporaryDirectory() as repo:
            with open(os.path.join(repo, "Dockerfile"), "w", encoding="utf-8") as f:
                f.write('FROM python:3.12-slim\nCMD ["python", "app.py"]\n')

            result = check_deployment_readiness(repo, "PASSED")
            self.assertEqual(result["build_method"], "docker")
            self.assertEqual(result["status"], "READY")

    def test_no_manifest_is_not_ready(self):
        with tempfile.TemporaryDirectory() as repo:
            result = check_deployment_readiness(repo, "PASSED")
            self.assertIsNone(result["build_method"])
            self.assertEqual(result["status"], "NOT_READY")

    def test_security_failure_blocks_readiness(self):
        with tempfile.TemporaryDirectory() as repo:
            module = os.path.join(repo, "myproject")
            os.makedirs(module)
            with open(os.path.join(module, "pom.xml"), "w", encoding="utf-8") as f:
                f.write("<project></project>")

            result = check_deployment_readiness(repo, "FAILED")
            self.assertEqual(result["build_method"], "maven")
            self.assertEqual(result["status"], "NOT_READY")


if __name__ == "__main__":
    unittest.main()
