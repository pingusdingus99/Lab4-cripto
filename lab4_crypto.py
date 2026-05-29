import sys
from Crypto.Cipher import DES, DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

# Tamaños nativos de clave e IV para cada algoritmo de criptografía simétrica:
# DES:     Clave de 8 bytes,  IV de 8 bytes
# 3DES:    Clave de 24 bytes, IV de 8 bytes
# AES-256: Clave de 32 bytes, IV de 16 bytes

# Config para elegir que algoritmo utilizar mediante selección numérica en bash
CONFIG = {
    "1": {"nombre": "DES",     "key_size": 8,  "iv_size": 8,  "cipher_mod": DES},
    "2": {"nombre": "3DES",    "key_size": 24, "iv_size": 8,  "cipher_mod": DES3},
    "3": {"nombre": "AES-256", "key_size": 32, "iv_size": 16, "cipher_mod": AES}
}

def ajustar_clave(nombre_algo, key_usuario, tamano_requerido):

    # Toma la clave del usuario y la fuerza a cumplir el tamaño del algoritmo.
    key_bytes = key_usuario.encode('utf-8')
    tamano_actual = len(key_bytes)
    
    if tamano_actual < tamano_requerido:
        # Si falta texto, rellenamos el espacio con bytes aleatorios seguros
        faltantes = tamano_requerido - tamano_actual
        print(f"  Alerta: Clave corta ({tamano_actual} bytes). Añadiendo {faltantes} bytes aleatorios.")
        return key_bytes + get_random_bytes(faltantes)
        
    elif tamano_actual > tamano_requerido:
        # Si sobra texto, truncar la clave hasta el tamaño justo
        print(f"  Alerta: Clave larga ({tamano_actual} bytes). Truncando a los {tamano_requerido} bytes requeridos.")
        return key_bytes[:tamano_requerido]
        
    # Si mide justo lo necesario, se devuelve intacta
    return key_bytes

def ajustar_iv(iv_usuario, tamano_requerido):
    # Ajusta el IV del usuario rellenando con ceros si es corto o cortándolo si es largo.

    iv_bytes = iv_usuario.encode('utf-8')
    if len(iv_bytes) < tamano_requerido:
        return iv_bytes.ljust(tamano_requerido, b'\x00')
    return iv_bytes[:tamano_requerido]

def main():
    print("***** LABORATORIO 4 DE CRIPTOGRAFÍA: CIFRADO SIMÉTRICO CBC ******")
    print("1. Probar DES")
    print("2. Probar 3DES")
    print("3. Probar AES-256")
    print("4. Salir")
    
    opcion = input("[+] Seleccione una opción (1-4): ").strip()
    
    if opcion == "4" or opcion not in CONFIG:
        print("[*] Saliendo del programa.")
        sys.exit(0)
        
    # Extraemos la configuración del algoritmo elegido
    algo_info = CONFIG[opcion]
    nombre = algo_info["nombre"]
    
    print(f"\n*** CONFIGURACIÓN PARA {nombre} ***")
    texto_plano = input("[+] Ingrese el texto a cifrar: ")
    key_usuario = input(f"[+] Ingrese la Clave (Recomendado {algo_info['key_size']} caracteres): ")
    iv_usuario  = input(f"[+] Ingrese el IV (Recomendado {algo_info['iv_size']} caracteres): ")
    
    print("\n*** PROCESAMIENTO Y AJUSTES ***\n")
    
    # Ajustar Key e IV
    key_final = ajustar_clave(nombre, key_usuario, algo_info["key_size"])
    iv_final = ajustar_iv(iv_usuario, algo_info["iv_size"])
    
    print(f"  [*] Key final utilizada (Hex): {key_final.hex()}")
    print(f"  [*] IV final utilizado  (Hex): {iv_final.hex()}\n")
    
    # Obtener el módulo del cifrador (DES, DES3 o AES)
    cipher_mod = algo_info["cipher_mod"]
    block_size = algo_info["iv_size"] # El tamaño del bloque de cifrado coincide con el del IV
    
    try:
        # Proceso del cifrado

        # Como estos algoritmos cifran en bloques cerrados, usamos pad() 
        # bajo el estándar PKCS7 para rellenar el texto sobrante.
        texto_con_padding = pad(texto_plano.encode('utf-8'), block_size)
        
        # Inicializamos el cifrador pasándole la Clave, el modo CBC y el IV
        objeto_cifrador = cipher_mod.new(key_final, cipher_mod.MODE_CBC, iv_final)
        
        # Ciframos los bytes reales y el resultado binario se pasa a Base64
        # para que se pueda imprimir y copiar fácilmente en bash o la terminal que sea.
        bytes_cifrados = objeto_cifrador.encrypt(texto_con_padding)
        ciphertext_base64 = base64.b64encode(bytes_cifrados).decode('utf-8')
        
        # Proceso del descifrado

        # En CBC los objetos guardan estado interno. Para descifrar,
        # obligatoriamente se crea un objeto nuevo idéntico al original.
        objeto_descifrador = cipher_mod.new(key_final, cipher_mod.MODE_CBC, iv_final)
        
        # Hacemos el camino inverso: decodificamos el Base64 a bytes crudos,
        # desciframos y luego removemos el padding PKCS7 sobrante.
        bytes_decodificados = base64.b64decode(ciphertext_base64)
        texto_con_padding_recuperado = objeto_descifrador.decrypt(bytes_decodificados)
        texto_descifrado = unpad(texto_con_padding_recuperado, block_size).decode('utf-8')
        
        # Mostrar outputs en pantalla
        print("-" * 50)
        print(f"  [✔] Texto Cifrado (Base64): {ciphertext_base64}")
        print(f"  [✔] Texto Descifrado:       {texto_descifrado}")
        print("-" * 50)
        
    except Exception as e:
        print(f"  Error durante el proceso criptográfico: {str(e)}")

if __name__ == "__main__":
    main()