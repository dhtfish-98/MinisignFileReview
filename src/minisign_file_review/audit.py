from .common import *
from .crypto import *
def lines(text):
    out=text.split(chr(10))
    if out and out[-1]=='':out.pop()
    return [s.removesuffix(chr(13)) for s in out]
def audit(d):
    fields(d,['file','public_key','signature'],['allow_legacy'])
    allow_legacy=boolean(d.get('allow_legacy',False))
    contents=read(d['file'],16777216);pktext=lines(string(d['public_key'],4096))
    if len(pktext)==2:need(pktext[0].startswith('untrusted comment: '),"invalid public key comment");pktext=pktext[1:]
    need(len(pktext)==1,"invalid public key format");pk=b64(pktext[0],limit=42);need(len(pk)==42 and pk[:2]==b'Ed',"unsupported public key format")
    parts=lines(string(d['signature'],8192));need(len(parts)==4,"signature requires four lines")
    need(parts[0].startswith('untrusted comment: ') and parts[2].startswith('trusted comment: '),"invalid comment prefixes")
    sig=b64(parts[1],limit=74);global_sig=b64(parts[3],limit=64)
    need(len(sig)==74 and len(global_sig)==64 and sig[2:10]==pk[2:10],"invalid signature or key identifier mismatch")
    mode=sig[:2];need(mode in (b'ED',b'Ed'),"unknown signature algorithm")
    if mode==b'Ed':need(allow_legacy,"legacy signatures require explicit opt-in")
    message=hashlib.blake2b(contents,digest_size=64).digest() if mode==b'ED' else contents
    comment=parts[2][len('trusted comment: '):];need(comment and all(c==chr(9) or (ord(c)>=32 and not 127<=ord(c)<=159 and not 0xD800<=ord(c)<=0xDFFF) for c in comment),"unsupported trusted comment")
    key=ed25519.Ed25519PublicKey.from_public_bytes(pk[10:]);verify(key,sig[10:],message,'Ed25519');verify(key,global_sig,sig[10:]+comment.encode('utf-8'),'Ed25519')
    return report(verified=True,file_sha256=hashlib.sha256(contents).hexdigest(),key_sha256=fingerprint(key),trusted_comment_sha256=hashlib.sha256(comment.encode('utf-8')).hexdigest(),mode=mode.decode())
