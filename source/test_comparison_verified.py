import unittest
from unittest.mock import patch
import compare_bound_control as c
from hybrid_rsa_mlkem import generate_keypair, encrypt

class ComparisonVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pk, cls.sk=generate_keypair()
        cls.original=encrypt('hybrid',pk,c.MESSAGE,c.AAD)

    def test_component_removal_preserves_other_fields(self):
        altered, aad=c.mutation(self.original,'ML-KEM bytes removed with consistent lengths')
        old=c.fields(self.original); new=c.fields(altered)
        self.assertEqual(new[1],old[1])
        self.assertEqual(new[2],b'')
        self.assertEqual(new[3:],old[3:])
        self.assertEqual(len(self.original)-len(altered),1088)
        self.assertEqual(aad,c.AAD)

    def test_mode_unchanged(self):
        altered,_=c.mutation(self.original,'ML-KEM bytes removed with consistent lengths')
        self.assertEqual(altered[5],3)
        self.assertEqual(altered[5],self.original[5])

    def test_bad_expected_exception_is_detected(self):
        # Change the oracle for one row: the verifier must fail.
        wrong={k:dict(v) for k,v in c.EXPECTED.items()}
        wrong['HXM1']['version changed']=('ValueError','incorrect expected error')
        with patch.object(c,'EXPECTED',wrong), self.assertRaises(AssertionError):
            c.run(output_dir='/tmp/hxm1_wrong_expected_result')

    def test_comparison_success(self):
        rows=c.run(output_dir='/tmp/hxm1_verified_unit_test')
        self.assertEqual(len(rows),12)
        self.assertTrue(all(r['outcome']=='EXPECTED_REJECTION' for r in rows))

if __name__=='__main__': unittest.main()
