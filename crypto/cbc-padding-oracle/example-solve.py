#!/usr/bin/env python3
from base64 import b64decode

# CBC padding oracle attack
# - lenerd

import requests
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret_data import encryption_key, secret
import secrets


def test_systems_security(base_url):
    new_ciphertext = bytes.fromhex(
        '2cc9a9fc7cb4dc60f1df7babc4bf82c1122b12cbd8a1c10e1d7f1d4cf57c60ed8cb3703e30ff4b1a2a9af418df999c71b331721a24e713668d0478351a4ccad77fa6abff498d919b3773e6e25fcad5556545a6339b9d4f42c854f96e940a538342424242424242424242424242424242')
    res = requests.get(f'{base_url}/quote/', cookies={'authtoken': new_ciphertext.hex()})
    print(f'[+] done:\n{res.text}')


def single_block_attack(BLOCKSIZE, ciphertextBlock, url):
    # Create an empty IV of block size
    zeroingIV = initZeroingVector(BLOCKSIZE)

    for pad_val in range(1, BLOCKSIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroingIV]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)

            assert len(iv) == 16
            assert len(ciphertextBlock) == 16

            if oracle(iv, ciphertextBlock, url):
                if pad_val == 1:
                    # make sure the padding really is of length 1 by changing
                    # the penultimate block and querying the oracle again
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, ciphertextBlock, url):
                        continue  # false positive; keep searching
                break

        print(pad_val)
        zeroingIV[-pad_val] = candidate ^ pad_val
    return zeroingIV


def oracle(iv, block, url):
    new_cookie = iv.hex() + block.hex()
    res = requests.get(f'{url}/quote/', cookies={'authtoken': new_cookie})
    # print(f'{res.text}')
    if "incorrect" not in res.text:
        print(f'{res.text}')

    if "No quote for you!" in res.text:
        return True

    if "invalid start byte" in res.text:
        # print(f'[+] done:\n{res.text}')
        return True

    if "invalid continuation byte" in res.text:
        return True

    if "unexpected end of data" in res.text:
        return True

    return False


def initZeroingVector(size):
    return [0] * size


def splitCookie(cookie: bytes, blockSize: int):
    iv = cookie[0:blockSize]
    print(len(iv))
    assert len(iv) == blockSize

    ciphertext = cookie[blockSize:]
    print(len(ciphertext))
    print(len(ciphertext) + len(iv))
    assert len(ciphertext) == len(cookie) - blockSize

    return iv, ciphertext


def full_attack(url):
    # Contact server for cookie (IV:CT)
    #url = 'http://localhost:5000/'
    response = requests.get(url)
    text = response.text
    print(text)

    BLOCKSIZE = 16  # Size of plaintext block, ciphertext block and IV

    cookie = response.cookies['authtoken']
    print("Cookie from website", cookie)

    assert len(cookie) % BLOCKSIZE == 0

    # Divide cookie up into IV that is prepended to the ciphertext and the ciphertext
    iv, ciphertext = splitCookie(bytes.fromhex(cookie), BLOCKSIZE)

    """Given the iv, ciphertext, and a padding oracle, finds and returns the plaintext"""
    assert len(iv) == BLOCKSIZE and len(ciphertext) % BLOCKSIZE == 0

    cbcMsg = iv + ciphertext

    # Create Block from the cookie.
    blocks = []
    for i in range(0, len(cbcMsg), BLOCKSIZE):
        blocks.append(cbcMsg[i: i + BLOCKSIZE])
    # blocks = [msg[i:i + BLOCKSIZE] for i in range(0, len(msg), BLOCKSIZE)]
    result = b''
    other = b''

    # loop over pairs of consecutive blocks performing CBC decryption on them
    iv = blocks[0]
    other += iv

    for ciphertextBlock in blocks[1:]:
        dec = single_block_attack(BLOCKSIZE, ciphertextBlock, url)
        other += bytes(dec)
        if ciphertextBlock == blocks[-1]:
            print(bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec)).decode("ascii"))
        plaintext = bytes(iv_byte ^ dec_byte for iv_byte, dec_byte in zip(iv, dec))
        result += plaintext
        iv = ciphertextBlock
        # break


    return unpad(result, 16).decode(), other
    
def cbc_encrypt(input_secret):
    plaintext = f"{input_secret} plain CBC is not secure!".encode()
    print("Byte length plaintext:", len(plaintext))
    padded_plain = pad(plaintext, 16)
    padding_length = len(padded_plain) - len(plaintext)
    print("Padding length:", padding_length)

    print("padded", padded_plain)
    
    url = 'http://localhost:5000/'

    current_cipher_block = secrets.token_bytes(16)
    full_ciphertext = current_cipher_block
    for plain_byte_number in range(0, len(padded_plain), 16):
        print("plain byte:", plain_byte_number)
        previous_cipher_block = secrets.token_bytes(16)

        start_byte = -(16+(plain_byte_number))
        end_byte = -plain_byte_number
        #print("Start, end byte", start_byte, end_byte)

        current_plain_block = padded_plain[start_byte:]
        if plain_byte_number > 0:
            current_plain_block = padded_plain[start_byte:end_byte]


        print("current plain:", current_plain_block)
        decrypted_block = single_block_attack(16, current_cipher_block, url)
        for byte in range(15, -1, -1):
            for candidate in range(256):
                if decrypted_block[byte] ^ candidate == current_plain_block[byte]:
                    temp = bytearray(previous_cipher_block)
                    temp[byte] = candidate
                    previous_cipher_block = bytes(temp)
                    break
        #print("cipher block", current_cipher_block)
        '''
        aes = AES.new(encryption_key, AES.MODE_CBC, iv=previous_cipher_block)
        # decrypt the ciphertext
        temp_plain = aes.decrypt(full_ciphertext)
        print("\nplaintext so far", temp_plain)
        print()'''
        full_ciphertext = previous_cipher_block + full_ciphertext
        current_cipher_block = previous_cipher_block
    
    res = requests.get(f'{url}/quote/', cookies={'authtoken': full_ciphertext.hex()})
    print("res", res.text)
    return res



def full_attack_plus_encrypt(url):

    plain = f'You never figure out that "{secret}". :)'
    decrypted_plain, _ = full_attack(url)
    print("Plain:", decrypted_plain)
    secret = decrypted_plain[27:-5]
    print(secret)
    
    cbc_encrypt(secret)
    print("Secret:", secret)
    

    

if __name__ == '__main__':
    url = 'http://localhost:5000/'
    full_attack_plus_encrypt(url)
    
