import requests
import base64
import json
import math
from fractions import Fraction

verifyFlag = False

def sign_message(url, message: str):
    request = requests.get(url=url+"/sign_random_document_for_students/" + message.encode().hex(), verify=verifyFlag)
    return request.text

def get_public_key(url):
    return json.loads(requests.get(url+"/pk", verify=verifyFlag).text)

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string -> encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string -> decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str

def extract_msg_signature(signature):
    js = json.loads(signature)
    return js['msg'], js['signature']

def get_12_and_quote(url):
    pk = get_public_key(url)
    N = pk['N']

    m1 = 'You got a 12 because you are an excellent student! :)'.encode()
    m1_int = int.from_bytes(m1, "big")

    #m = x*y
    
    x = 1
    for i in range(2, m1_int):
        gcd = math.gcd(m1_int, i)
        if gcd > 1:
            x = gcd
            break

    print(x)
    y = int(Fraction(m1_int)/Fraction(x))

    print("m1", Fraction(m1_int))
    print("y*x", Fraction(y)*Fraction(x) % N)
    x_msg = x.to_bytes(math.ceil(x.bit_length() / 8.0), "big")
    y_msg = y.to_bytes(math.ceil(y.bit_length() / 8.0), "big")
    request = requests.get(url=url+"/sign_random_document_for_students/" + x_msg.hex(), verify=verifyFlag)
    print(request.text)
    x_msg, x_sign = extract_msg_signature(request.text)

    request = requests.get(url=url+"/sign_random_document_for_students/" + y_msg.hex(), verify=verifyFlag)
    #print(request.text)
    y_msg, y_sign = extract_msg_signature(request.text)

    m3 = int.from_bytes(bytes.fromhex(x_msg), "big") * int.from_bytes(bytes.fromhex(y_msg), "big") % N
    m3 = m3.to_bytes(math.ceil(m3.bit_length() / 8.0), "big")
    print(m3.decode())

    s3 = int.from_bytes(bytes.fromhex(x_sign), "big") * int.from_bytes(bytes.fromhex(y_sign), "big") % N
    s3 = s3.to_bytes(math.ceil(s3.bit_length() / 8.0), "big")
    #print("s3",s3)
    j3 = json.dumps({'msg': m3.hex(), 'signature': s3.hex()})
    custom_cookie = json_to_cookie(j3)

    res = requests.get(url + "/grade", cookies={'grade':custom_cookie}, verify=verifyFlag)
    print(res.text)
    res = requests.get(url + "/quote", cookies={'grade':custom_cookie}, verify=verifyFlag)
    print(res.text)

if __name__ == '__main__':
    url = 'http://localhost:5000'
    url = 'https://cbc-rsa.syssec.dk:8001'
    get_12_and_quote(url)
    #req = requests.get(url + "/pk", verify=verifyFlag)
    #print(req.text)