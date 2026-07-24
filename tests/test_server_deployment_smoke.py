import unittest

from scripts.qa.server_deployment_smoke import run_checks


class ServerDeploymentSmokeTests(unittest.TestCase):
    def test_server_deployment_smoke_checks_pass(self):
        result = run_checks()

        self.assertTrue(result["ok"], result["failed"])
        self.assertGreaterEqual(result["checks_total"], 10)
        self.assertEqual(result["checks_failed"], 0)


if __name__ == "__main__":
    unittest.main()
