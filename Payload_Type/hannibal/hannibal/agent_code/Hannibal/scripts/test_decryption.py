"""
This is code I used when troubleshooting formatting the messages as Mythic expects them.
You can use it to convert the b64 encryption key into a c-style byte array.
TODO: Clean this up.
"""

import base64
import json
import hashlib
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decode_base64(encoded_message):
    return base64.b64decode(encoded_message)

def verify_hmac(iv, encrypted_data, hmac_signature, key):
    data_to_verify = iv + encrypted_data
    computed_hmac = hmac.new(key, data_to_verify, hashlib.sha256).digest()
    return hmac.compare_digest(computed_hmac, hmac_signature)

def decrypt_aes256_cbc(encrypted_data, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data

def main():



    base64_message = "MDdjMTNkYmMtM2U3NC00YmZiLWIxMzYtNzdjMWY1ZGZhMzVkb+eDWjmnxRP7hFqD1D2YKl/FAPQ14s9ohnMddW2u9bNp/zxbijUvEIZeoaLcCD1tvDnzGuTEq5CbNwAhIvG8Dc0KCVGNw8Fr9lBZ7eGMCVuRi4iwQ3F8TW/Vms7UZZY6BHUAGnR74WrJLPA8EGinwhC6JcFq/+RzzC0oRFmFdZhb/OImN5lrdMaJy/tyfTpeb+Q6m/ReRP8c2kYqcryno7BcxMB3C0pG0R8B0NS8wVshXxLOsiGcqKIqjKPTjG5kkzfpDofR9VHYEgM91arhAIL1sCeEy6aMeyDewV+6S2j0kZyrm8QstF2OeKRMtHXzdSOlDrUbaXtvcb2erDz1yVsYuiAweIhvNGCYflFPsqs="
    key = base64.b64decode("1jbinOVw/xh3wEIK9jUOGdiXOh7FuLQBgf3+4uWEkng=")
    # Your base64 encoded message and key
    # base64_message = "ODA4NDRkMTktOWJmYy00N2Y5LWI5YWYtYzZiOTE0NGMwZmRjyHcKh56jliiv87ReJE7QqK8edpLcV5cfywt8Lg1jWJzPc8b37zB9/mliG1HKH0dyF/jZqiSzUfSWEjgfhKa3DoLUqJOvnbpOYYsL3GvfWrps3/HQhZogSjwXnQmTehbADhXrOqA4622YMFjJbpykxdq7kpufn+12GDidwNybOlbg9ej8D/PpZVVdqL2RdASe"
    # key = base64.b64decode("hfN9Nk29S8LsjrE9ffbT9KONue4uozk+/TVMyrxDvvM=")

    # Step 1: Decode the base64 encoded message
    decoded_message = decode_base64(base64_message)

    # Step 2: Extract the components
    uuid_size = 36  # UUID string size (36 bytes)
    iv_size = 16    # AES block size (16 bytes)
    uuid = decoded_message[:uuid_size]
    iv = decoded_message[uuid_size:uuid_size + iv_size]
    hmac_signature = decoded_message[-32:]  # HMAC-SHA256 output size is 32 bytes
    encrypted_msg = decoded_message[uuid_size + iv_size:-32]

    key_c_style = ", ".join(f"0x{byte:02x}" for byte in key)
    print("Key (C-style): {", key_c_style, "}")
    
    iv_c_style = ", ".join(f"0x{byte:02x}" for byte in iv)
    print("IV (C-style): {", iv_c_style, "}")

    # Print the HMAC in C-style array format
    hmac_c_style = ", ".join(f"0x{byte:02x}" for byte in hmac_signature)
    print("HMAC (C-style): {", hmac_c_style, "}")

    # Step 3: Verify the HMAC
    if not verify_hmac(iv, encrypted_msg, hmac_signature, key):
        print("HMAC verification failed!")
        return
    
    decrypted = decrypt_aes256_cbc(encrypted_msg, iv, key)

    print(decrypted)

    step = 1

    # # Step 4: Decrypt the encrypted JSON
    # decrypted_json_bytes = decrypt_aes256_cbc(encrypted_json, iv, key)
    # decrypted_json = json.loads(decrypted_json_bytes)

    # # Output the decrypted JSON
    # print("Decrypted JSON:", decrypted_json)

if __name__ == "__main__":
    main()
