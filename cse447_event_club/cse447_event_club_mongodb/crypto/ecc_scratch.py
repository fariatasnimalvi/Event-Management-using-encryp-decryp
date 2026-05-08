import secrets, json
# Educational toy curve: y^2 = x^3 + ax + b over prime field p.
p = 170141183460469231731687303715884105727  # 2^127-1
a = 2
b = 3
G = (3, 6)
O = None

def inv_mod(x): return pow(x % p, p-2, p)
def is_on_curve(P):
    if P is None: return True
    x,y=P; return (y*y - (x*x*x + a*x + b)) % p == 0

def add(P,Q):
    if P is None: return Q
    if Q is None: return P
    x1,y1=P; x2,y2=Q
    if x1==x2 and (y1+y2)%p==0: return None
    if P==Q:
        lam=((3*x1*x1+a)*inv_mod(2*y1))%p
    else:
        lam=((y2-y1)*inv_mod(x2-x1))%p
    x3=(lam*lam-x1-x2)%p
    y3=(lam*(x1-x3)-y1)%p
    return (x3,y3)

def mul(k,P=G):
    R=None; Q=P
    while k:
        if k&1: R=add(R,Q)
        Q=add(Q,Q); k//=2
    return R

def generate_keypair():
    d=secrets.randbelow(p-2)+1
    Q=mul(d)
    return {'public': {'Q': Q}, 'private': {'d': d}}

def encrypt_int(m, pub):
    k=secrets.randbelow(p-2)+1
    C1=mul(k)
    S=mul(k, tuple(pub['Q']))
    c2=(m + S[0]) % p
    tag=(m + S[1]) % p
    return (C1, c2, tag)

def decrypt_int(cipher, priv):
    C1,c2,tag=cipher
    C1=tuple(C1)
    S=mul(int(priv['d']), C1)
    m=(int(c2)-S[0])%p
    if (m+S[1])%p != int(tag):
        raise ValueError('ECC integrity check failed')
    return m

def encrypt_bytes(data: bytes, pub):
    size=14
    chunks=[]
    for i in range(0,len(data),size):
        part=data[i:i+size]
        m=int.from_bytes(part,'big')
        C1,c2,tag=encrypt_int(m,pub)
        chunks.append({'C1': list(C1), 'c2': c2, 'tag': tag, 'l': len(part)})
    return json.dumps(chunks)

def decrypt_bytes(token: str, priv):
    chunks=json.loads(token); out=b''
    for it in chunks:
        m=decrypt_int((it['C1'], it['c2'], it['tag']), priv)
        out += int(m).to_bytes(int(it['l']),'big')
    return out

def encrypt_text(text, pub): return encrypt_bytes(text.encode(), pub)
def decrypt_text(token, priv): return decrypt_bytes(token, priv).decode()
