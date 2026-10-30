import unittest
from cloudsec_check import evaluate

class CloudSecTests(unittest.TestCase):
    def test_secure_values_pass(self):
        r=evaluate({"storage":{"public_access":False},"logging":{"enabled":True},
          "identity":{"mfa_required":True,"least_privilege":True},
          "encryption":{"at_rest":True,"in_transit":True},"backup":{"enabled":True}})
        self.assertEqual(r["summary"]["review"],0)
        self.assertEqual(r["summary"]["unknown"],0)
    def test_missing_values_unknown(self):
        self.assertEqual(evaluate({})["summary"]["unknown"],7)
if __name__ == "__main__": unittest.main()
