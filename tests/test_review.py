import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from minisign_file_review import audit
from minisign_file_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','minisign_file_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class MinisignTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.file=pathlib.Path(self.t.name)/'artifact';self.file.write_bytes(b'public synthetic artifact');self.k=ed25519.Ed25519PrivateKey.generate();self.kid=b'12345678';pub=self.k.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw);message=hashlib.blake2b(self.file.read_bytes(),digest_size=64).digest();sig=self.k.sign(message);comment='synthetic verification vector'
        self.d={'file':str(self.file),'public_key':enc(b'Ed'+self.kid+pub),'signature':'untrusted comment: test\n'+enc(b'ED'+self.kid+sig)+'\ntrusted comment: '+comment+'\n'+enc(self.k.sign(sig+comment.encode()))+'\n'}
    def tearDown(self):self.t.cleanup()
    def test_valid_and_tampering(self):
        self.assertTrue(audit(self.d)['verified'])
        for changed in ('changed comment',):
            d=copy.deepcopy(self.d);d['signature']=d['signature'].replace('synthetic verification vector',changed)
            with self.assertRaises(ReviewError):audit(d)
        self.file.write_bytes(b'changed')
        with self.assertRaises(ReviewError):audit(self.d)
    def test_legacy_requires_optin(self):
        sig=self.k.sign(self.file.read_bytes());comment='legacy';self.d['signature']='untrusted comment: legacy\n'+enc(b'Ed'+self.kid+sig)+'\ntrusted comment: legacy\n'+enc(self.k.sign(sig+comment.encode()))+'\n'
        with self.assertRaises(ReviewError):audit(self.d)
        self.d['allow_legacy']=True;self.assertTrue(audit(self.d)['verified'])
    def test_saved_example(self):
        if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':
            project=pathlib.Path(__file__).resolve().parents[1];d=json.loads((project/'examples/valid.json').read_text());d['file']=str(project/d['file']);self.assertEqual(audit(d)['status'],'PASS');return
        out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True);(out/'artifact.bin').write_bytes(self.file.read_bytes());d=copy.deepcopy(self.d);d['file']='examples/artifact.bin';save_example(d)

if __name__=="__main__":unittest.main()
