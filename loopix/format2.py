from os import urandom
from collections import namedtuple
from binascii import hexlify
from copy import copy
import math

from hashlib import sha512, sha1
import hmac

from petlib.ec import EcGroup
from petlib.bn import Bn
from petlib.cipher import Cipher

Keys = namedtuple('Keys', ['b', 'iv', 'kmac', 'kenc'])


def KDF(element, idx="A"):
    ''' The key derivation function for b, iv, and keys '''
    keys = sha512(element + idx).digest()
    return Keys(keys[:16], keys[16:32], keys[32:48], keys[48:64])


def setup():
    ''' Setup the parameters of the mix crypto-system '''
    G = EcGroup()
    o = G.order()
    g = G.generator()
    o_bytes = int(math.ceil(math.log(float(int(o))) / math.log(256)))
    return G, o, g, o_bytes


def mix_package(sender, receiver, triplets, dest_message = '', return_message=''):
    ''' Package a message through a mix-net. '''

    aes = Cipher("AES-128-CTR")

    Bs = []

    _, ypub, y = sender
    pubs = [ ypub ]

    round_trip = triplets + [ receiver ] + list(reversed(triplets))

    secrets = []
    prod_bs = Bn(1)
    for i, (mname, mpub, msec) in enumerate(round_trip):
        xysec2 = (y * prod_bs) * mpub
        secrets += [ xysec2 ]

        if __debug__ and msec is not None:
            xysec1 = (msec *  prod_bs) * ypub
            assert xysec2  == xysec1

        # Blinding factor
        k = KDF(xysec2.export())
        b = Bn.from_binary(k.b) % o
        Bs += [ b ]

        prod_bs = (b * prod_bs) % o
        pubs += [ prod_bs * ypub ]

    # Precompute the correction factors
    correction_factors = []
    for i in range(len(triplets)):
        
        total_b = Bn(1)
        for j in range(i, 2 * len(triplets) - i):
            total_b = (total_b * Bs[j]) % o

        if __debug__:
            assert round_trip[i][0] ==  round_trip[2 * len(triplets) - i][0]
            assert total_b * pubs[i] == pubs[2 * len(triplets) - i]

        correction_factors += [ total_b ]

    all_factors = copy(correction_factors)
    all_factors += [ Bn(1) ]
    all_factors += [bf.mod_inverse(o) for bf in reversed(correction_factors)]

    if __debug__:
        assert len(all_factors) == len(round_trip)

    # Derive all keys
    all_keys = []    
    for bs, Ksec in zip(all_factors, secrets):

        k1 = KDF(Ksec.export())
        k2 = KDF( (bs * Ksec).export())

        all_keys += [(k1, k2)]
        
    # Generate data stream
    data = [ sender ] + round_trip + [ sender ]
    addressing = []
    for i, _ in enumerate(round_trip):
        addressing += [(data[1 + i-1][0], data[1 + i+1][0])]

    all_data = zip(round_trip, all_factors, pubs, addressing, all_keys) 

    # Build the backwards path
    prev = return_message
    backwards_stages = [ ]
    for j in range(len(mix_names) + 1):
        (mname, mpub, msec), bs, yelem, (xfrom, xto), (k1, k2) = all_data[j]
        the_bs = bs.mod_inverse(o).binary()
        
        enc = aes.enc(k2.kenc, k2.iv)
        ciphertext = enc.update("1" + xto + xfrom + prev)
        ciphertext += enc.finalize()

        mac = hmac.new(k2.kmac, ciphertext, digestmod=sha1).digest()

        prev = mac + ciphertext
        backwards_stages += [ prev ]

    # Build the forwards path
    prev = dest_message
    forwards_stages = []
    for jp in range(len(mix_names) + 1):
        j = len(mix_names) - jp

        (mname, mpub, msec), bs, yelem, (xfrom, xto), (k1, k2) = all_data[j]
        the_bs = bs.binary()
        
        enc = aes.enc(k1.kenc, k1.iv)
        ciphertext = enc.update("0" + xfrom + xto + the_bs + prev)
        ciphertext += enc.finalize()

        mac = hmac.new(k1.kmac, ciphertext, digestmod=sha1).digest()

        prev = mac + ciphertext
        forwards_stages += [ prev ]

    forwards_stages = list(reversed(forwards_stages))

    stages = zip(forwards_stages, backwards_stages)

    # Check all the MACs
    if __debug__:
        for j in range(len(mix_names) + 1):
            (msg_f, msg_b) = stages.pop(0)

            (mname, mpub, msec), bs, yelem, (xfrom, xto), (k1, k2) = all_data[j]
            
            mac1 = hmac.new(k1.kmac, msg_f[20:], digestmod=sha1).digest()
            assert msg_f[:20] == mac1

            enc = aes.dec(k1.kenc, k1.iv)        
            plaintext = enc.update(msg_f[20:])
            plaintext += enc.finalize()

            assert xfrom == plaintext[1:5] and xto == plaintext[5:9]

            mac2 = hmac.new(k2.kmac, msg_b[20:], digestmod=sha1).digest()
            assert msg_b[:20] == mac2
    # End __debug__

    return zip(pubs[:len(mix_names) + 1], forwards_stages + [ dest_message ], [ return_message ] + backwards_stages)

def mix_operate(message, triplet, setup, generate_return_message=False):
    mname, mpub, msec = triplet
    elem, forward, backwards = message
    G, o, g, o_bytes = setup

    aes = Cipher("AES-128-CTR")

    # Derive first key
    k1 = KDF((msec * elem).export())

    # Derive the blinding factor
    b = Bn.from_binary(k1.b) % o
    new_elem = b * elem

    # Check the forward MAC
    mac1 = hmac.new(k1.kmac, forward[20:], digestmod=sha1).digest()
    if not (forward[:20] == mac1):
        raise Exception("Wrong MAC1")

    # Decrypt the payload
    enc = aes.dec(k1.kenc, k1.iv)        
    pt = enc.update(forward[20:])
    pt += enc.finalize()

    # Parse the forward message
    xcode = pt[0]
    if not (xcode == "0" or xcode == "1"):
        raise Exception("Wrong routing code")

    pt = pt[1:]

    if xcode == "0":

        xfrom, xto, the_bs, new_forw = pt[:4], pt[4:8], pt[8:8+o_bytes], pt[8+o_bytes:]
        old_bs = Bn.from_binary(the_bs)

        # Now package the return part
        k2 = KDF(((msec * old_bs) * elem).export())
            
        enc = aes.enc(k2.kenc, k2.iv)
        new_back_body = enc.update("1" + xto + xfrom + backwards)
        new_back_body += enc.finalize()
        mac2 = hmac.new(k2.kmac, new_back_body, digestmod=sha1).digest()

        new_back = mac2 + new_back_body

        if generate_return_message:
            ret_elem = old_bs * elem
            ret_forw = new_back
            ret_back = None
            
            return ((xto, xfrom), (ret_elem, ret_forw, ret_back) )            

    else:

        xfrom, xto, new_forw = pt[:4], pt[4:8], pt[8:]

        # Returns do not need to build returns
        if not (backwards == None):
            raise Exception("Backwards header should be None")

        new_back = None

    return ((xfrom, xto), (new_elem, new_forw, new_back) )


if __name__ == "__main__":

    G, o, g, o_bytes = setup()

    # The mix secrets
    mix_secrets = [o.random() for _ in range(10)]
    mix_pubs    = [x * g for x in mix_secrets]
    mix_names   = ["M%03d" % i for i in range(10)]

    triplets = zip(mix_names, mix_pubs, mix_secrets)

    # Client secret
    y = o.random()
    ypub = y * g
    sender   = ("ALI_", ypub, y)

    # Receiver secrets
    rx = o.random()
    receiver = ("BOB_", rx * g, rx)

    # Package a mix message ready to send
    msgs = mix_package(sender, receiver, triplets)
    # Note: msgs[0] is the message, msgs[i] are what it 
    # will be in all future mixing stages.

    print "Size:", map(len, [msgs[0][0].export(), msgs[0][1],msgs[0][2]])

    # Check that every stage of mixing yields the next message
    for i in range(len(triplets)):
        _, msg2 = mix_operate(msgs[i], triplets[i], (G, o, g, o_bytes))
        assert msg2 == msgs[i+1]

    # Ensure that the message can be returned as well.
    _, ret_msg = mix_operate(msgs[5], triplets[5], (G, o, g, o_bytes), True)
    (xf, xt), check_ret = mix_operate(ret_msg, triplets[5], (G, o, g, o_bytes))
    