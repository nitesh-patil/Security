import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class CustomAesGCM():

    def __init__(self,key,data):
        self.key = key
        self.data = data
    def aes_gcm_encrypt(self):
        key = self.key
        data = self.data
        flag = data.encode('utf-8')
        key = base64.urlsafe_b64decode(bytes(key, 'utf-8') + b'===')
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM,nonce)
        ciphertext, tag = cipher.encrypt_and_digest(flag)
        enc = nonce + ciphertext + tag
        # enc = base64.b64encode(enc).decode("utf-8")
        urlSafeEncodedBytes = base64.urlsafe_b64encode(enc)
        urlSafeEncodedStr = str(urlSafeEncodedBytes, "utf-8")
        return urlSafeEncodedStr


    def aes_gcm_decrypt(self):
        key = self.key
        data = self.data
        dt = base64.urlsafe_b64decode(bytes(data, 'utf-8') + b'===')
        key = base64.urlsafe_b64decode(bytes(key, 'utf-8') + b'===')
        nonce, tag = dt[:12], dt[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce)
        decrypted = cipher.decrypt_and_verify(dt[12:-16], tag).decode("utf-8")
        return decrypted






#Example :
key = 'exwjQmaQfqp8clfMvnkw7CuBN73kecfSPfPoKsYaWQF'
data = 'The OTP token for your accountt 1234567 is a0bcdef .Please enter the OTP to login into your acctount.'

#encryption
encrypted_data = CustomAesGCM(key,data).aes_gcm_encrypt()
print("Encrypted => "+str(encrypted_data))


#decryption
decrypted_data = CustomAesGCM(key,encrypted_data).aes_gcm_decrypt()
print("Decrypted => "+str(decrypted_data))
