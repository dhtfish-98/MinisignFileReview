import unittest,json,sys,subprocess,copy,base64,hashlib,datetime
from minisign_file_review import audit
from minisign_file_review.common import ReviewError,load
import test_review as fixtures
def reject(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','minisign_file_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
    out=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(out['status'],'FAIL');test.assertFalse(out['complete']);test.assertFalse(out.get('verified',False))
class FiniteInputTests(unittest.TestCase):
    def test_exponent_overflow_rejected_api_and_cli(self):
        for raw in (b'{"x":1e999}',b'{"x":[-1e999]}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','minisign_file_review','-'],input=raw,capture_output=True,timeout=10);out=json.loads(p.stdout)
            self.assertEqual(p.returncode,1);self.assertFalse(out['complete']);self.assertEqual(out['status'],'FAIL')
        self.assertEqual(load(b'{"x":1.25}'),{'x':1.25})
    def test_unknown_fields_error_does_not_echo_canary(self):
        canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        with self.assertRaises(ReviewError) as e:audit({canary:canary})
        self.assertNotIn(canary,str(e.exception))
        p=subprocess.run([sys.executable,'-m','minisign_file_review','-'],input=json.dumps({canary:canary}).encode(),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())
class LegacySwitchTests(unittest.TestCase):
    def test_switch_type_checked_for_prehashed_signature_api_cli(self):
        t=fixtures.MinisignTests();t.setUp()
        try:
            self.assertTrue(audit(t.d)['verified'])
            for value in ('yes',1,None,[],{}):reject(self,{**t.d,'allow_legacy':value})
            for value in (False,True):self.assertTrue(audit({**t.d,'allow_legacy':value})['verified'])
        finally:t.tearDown()

class FilePlatformCapabilityTests(unittest.TestCase):
    def test_missing_or_unusable_file_flags_fail_closed(self):
        from unittest import mock
        from minisign_file_review.common import read
        from minisign_file_review import common
        for flag in ('O_NOFOLLOW','O_NONBLOCK'):
            for value in (None,0,'unusable'):
                with mock.patch.object(common.os,flag,value,create=True):
                    with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
            with mock.patch.object(common.os,flag,1,create=True):
                delattr(common.os,flag)
                with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
