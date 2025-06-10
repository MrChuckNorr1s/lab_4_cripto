import base64
from Crypto.Cipher import DES, DES3, AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def ajustar_clave(key_input, largo_requerido):
    key_bytes = key_input.encode()
    if len(key_bytes) < largo_requerido:
        key_bytes += get_random_bytes(largo_requerido - len(key_bytes))
    elif len(key_bytes) > largo_requerido:
        key_bytes = key_bytes[:largo_requerido]
    return key_bytes

def cifrar_des(texto, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    texto_padded = pad(texto.encode(), DES.block_size)
    cifrado = cipher.encrypt(texto_padded)
    return cifrado

def descifrar_des(cifrado, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    descifrado_padded = cipher.decrypt(cifrado)
    descifrado = unpad(descifrado_padded, DES.block_size).decode()
    return descifrado

def cifrar_3des(texto, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    texto_padded = pad(texto.encode(), DES3.block_size)
    cifrado = cipher.encrypt(texto_padded)
    return cifrado

def descifrar_3des(cifrado, key, iv):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    descifrado_padded = cipher.decrypt(cifrado)
    descifrado = unpad(descifrado_padded, DES3.block_size).decode()
    return descifrado

def cifrar_aes(texto, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    texto_padded = pad(texto.encode(), AES.block_size)
    cifrado = cipher.encrypt(texto_padded)
    return cifrado

def descifrar_aes(cifrado, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    descifrado_padded = cipher.decrypt(cifrado)
    descifrado = unpad(descifrado_padded, AES.block_size).decode()
    return descifrado

def main():
    print("Ingrese los datos requeridos para hacer cifrado simétrico:")

    des_key_input = input("\nPara el algoritmo DES, ingrese su clave (key), debe ser de 8 bytes: ")
    des_iv_input = input("Ingrese el IV, debe ser de 8 bytes: ")

    aes_key_input = input("\nPara el algoritmo AES-256, ingrese la clave (key), debe ser de 32 bytes: ")
    aes_iv_input = input("Ingrese el IV, debe ser de 16 bytes: ")

    trip_des_key_input = input("\nPara el algoritmo 3DES, ingrese su clave (key), debe ser de 24 bytes: ")
    trip_des_iv_input = input("Ingrese el IV, debe ser de 8 bytes: ")

    des_key = ajustar_clave(des_key_input, 8)
    des_iv = ajustar_clave(des_iv_input, 8)

    aes_key = ajustar_clave(aes_key_input, 32)
    aes_iv = ajustar_clave(aes_iv_input, 16)

    trip_des_key = ajustar_clave(trip_des_key_input, 24)
    trip_des_iv = ajustar_clave(trip_des_iv_input, 8)

    print(f"\nClave DES ajustada: {des_key.hex()}")
    print(f"IV DES ajustado: {des_iv.hex()}")

    print(f"\nClave AES ajustada: {aes_key.hex()}")
    print(f"IV AES ajustado: {aes_iv.hex()}")

    print(f"\nClave 3DES ajustada: {trip_des_key.hex()}")
    print(f"IV 3DES ajustado: {trip_des_iv.hex()}")

    texto_plano = input("\nIngrese el texto plano que desea cifrar: ")

    cifrado_des = cifrar_des(texto_plano, des_key, des_iv)
    print("\nDES - Texto cifrado (base64):", base64.b64encode(cifrado_des).decode())
    descifrado_des = descifrar_des(cifrado_des, des_key, des_iv)
    print("DES - Texto descifrado:", descifrado_des)

    cifrado_3des = cifrar_3des(texto_plano, trip_des_key, trip_des_iv)
    print("\n3DES - Texto cifrado (base64):", base64.b64encode(cifrado_3des).decode())
    descifrado_3des = descifrar_3des(cifrado_3des, trip_des_key, trip_des_iv)
    print("3DES - Texto descifrado:", descifrado_3des)

    cifrado_aes = cifrar_aes(texto_plano, aes_key, aes_iv)
    print("\nAES-256 - Texto cifrado (base64):", base64.b64encode(cifrado_aes).decode())
    descifrado_aes = descifrar_aes(cifrado_aes, aes_key, aes_iv)
    print("AES-256 - Texto descifrado:", descifrado_aes)

if __name__ == "__main__":
    main()
