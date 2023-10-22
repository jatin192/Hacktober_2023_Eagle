# dont give the name of file like crryptography beacuse when you want to run this file it will call inbuilt cryptography function
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def generate_public_private_key():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048,)
    public_key_m = private_key.public_key
    return public_key_m, private_key


def signature_func(message, pr):
    message = bytes(str(message), 'utf-8')
    signature = pr.sign(message, padding.PSS(mgf=padding.MGF1(
        hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature


def verification_fun(signature, message, pub):
    message = bytes(str(message), 'utf-8')
    try:
        pub.verify(signature, message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True

    except InvalidSignature:
        return False
    except:
        print("error occur oops!!")
        return False


if __name__ == '__main__':
    pub, pr = generate_public_private_key()
    print("public key ==", pub)
    print("private key ==", pr)
    message_m = "jatin"
    signature_m = signature_func(message_m, pr)
    print("signature ==", signature_m)

    correct = verification_fun(signature_m, message_m, pub)
    if correct:
        print("correct")
    else:
        print("Failed")
