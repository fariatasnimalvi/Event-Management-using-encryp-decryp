import secrets, math, json

def egcd(a,b):
    if b==0: return (a,1,0)
    g,x1,y1=egcd(b,a%b); return (g,y1,x1-(a//b)*y1)

def modinv(a,m):
    g,x,y=egcd(a,m)
    if g!=1: raise ValueError('no inverse')
    return x%m

def is_probable_prime(n, rounds=8):
    if n < 2: return False
    small=[2,3,5,7,11,13,17,19,23,29,31,37]
    for p in small:
        if n%p==0: return n==p
    d=n-1; s=0
    while d%2==0: s+=1; d//=2
    for _ in range(rounds):
        a=secrets.randbelow(n-3)+2
        x=pow(a,d,n)
        if x in (1,n-1): continue
        for __ in range(s-1):
            x=pow(x,2,n)
            if x==n-1: break
        else: return False
    return True

def gen_prime(bits=512):
    while True:
        n=secrets.randbits(bits) | (1<<(bits-1)) | 1
        if is_probable_prime(n): return n

def generate_keypair(bits=1024):
    e=65537
    while True:
        p=gen_prime(bits//2); q=gen_prime(bits//2)
        if p==q: continue
        phi=(p-1)*(q-1)
        if math.gcd(e,phi)==1:
            n=p*q; d=modinv(e,phi)
            return {'public': {'n': n, 'e': e}, 'private': {'n': n, 'd': d, 'p': p, 'q': q}}

def encrypt_int(m, pub):
    return pow(m, pub['e'], pub['n'])

def decrypt_int(c, priv):
    return pow(c, priv['d'], priv['n'])

def max_chunk_bytes(pub):
    return (pub['n'].bit_length()-1)//8

def encrypt_bytes(data: bytes, pub):
    size=max_chunk_bytes(pub)
    chunks=[]
    for i in range(0,len(data),size):
        part=data[i:i+size]
        m=int.from_bytes(part,'big')
        chunks.append({'c': encrypt_int(m,pub), 'l': len(part)})
    return json.dumps(chunks)

def decrypt_bytes(token: str, priv):
    chunks=json.loads(token)
    out=b''
    for item in chunks:
        m=decrypt_int(int(item['c']), priv)
        out += int(m).to_bytes(int(item['l']),'big')
    return out

def encrypt_text(text, pub): return encrypt_bytes(text.encode(), pub)
def decrypt_text(token, priv): return decrypt_bytes(token, priv).decode()
