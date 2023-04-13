import hashlib
import os

def clear_console():
    os.system('cls' if os.name=='nt' else 'clear')

def calcular_hash(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        md5_hash = hashlib.md5(data).hexdigest()
        aes_hash = hashlib.sha256(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha512_hash = hashlib.sha512(data).hexdigest()
        blake2b_hash = hashlib.blake2b(data).hexdigest()
        blake2s_hash = hashlib.blake2s(data).hexdigest()

        hashes = {
            "MD5": md5_hash,
            "AES": aes_hash,
            "SHA256": sha256_hash,
            "SHA512": sha512_hash,
            "BLAKE2b": blake2b_hash,
            "BLAKE2s": blake2s_hash,
        }

        return hashes
        
    except FileNotFoundError:
        print(f"El archivo {file_path} no existe.")
        return None
    except:
        print("Error al calcular el hash del archivo.")
        return None

def validar_integridad(file_path):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        original_hashes = calcular_hash(file_path)

        if not original_hashes:
            return False

        md5_hash = hashlib.md5(data).hexdigest()
        aes_hash = hashlib.sha256(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha512_hash = hashlib.sha512(data).hexdigest()
        blake2b_hash = hashlib.blake2b(data).hexdigest()
        blake2s_hash = hashlib.blake2s(data).hexdigest()

        hashes = {
            "MD5": md5_hash,
            "AES": aes_hash,
            "SHA256": sha256_hash,
            "SHA512": sha512_hash,
            "BLAKE2b": blake2b_hash,
            "BLAKE2s": blake2s_hash,
        }

        for hash_name, hash_value in hashes.items():
            if hash_value != original_hashes[hash_name]:
                return False

        return True
    except FileNotFoundError:
        print(f"El archivo {file_path} no existe.")
        return False
    except:
        print("Error al validar la integridad del archivo.")
        return False

def calcular_hash2(file_path, algorithm):
    """Calcula el hash de un archivo utilizando el algoritmo especificado."""
    hash_func = None
    if algorithm == "SHA256":
        hash_func = hashlib.sha256
    elif algorithm == "SHA512":
        hash_func = hashlib.sha512
    else:
        raise ValueError("Algoritmo de hash no válido")

    try:
        with open(file_path, "rb") as f:
            data = f.read()
            hash_value = hash_func(data).hexdigest()
    except FileNotFoundError:
        raise ValueError("Archivo no encontrado")
    except Exception as e:
        raise RuntimeError(f"Error al leer archivo: {str(e)}")

    return hash_value

def validar_integridad2(file_path, sha256_hash, sha512_hash):
    """Verifica la integridad de un archivo comparando los hashes proporcionados."""
    try:
        if not os.path.isfile(file_path):
            raise ValueError("Archivo no encontrado")

        calculated_sha256_hash = calcular_hash2(file_path, "SHA256")
        calculated_sha512_hash = calcular_hash2(file_path, "SHA512")
    except ValueError:
        raise
    except Exception as e:
        raise RuntimeError(f"Error al verificar integridad: {str(e)}")

    if calculated_sha256_hash != sha256_hash:
        return False
    if calculated_sha512_hash != sha512_hash:
        return False

    return True

def start():
    while True:
        print("---------------------------CHECKING * HASH---------------------------")
        print("\tBy karonte 2023\tv1")
        print("\nMenú de opciones")
        print("1. Ver los hashes del archivo.")
        print("2. Ver integridad del archivo.")
        print("3. Comparar SHA256 y SHA512.")
        print("4. Ver los hashes y la integridad del archivo.")
        print("5. Limpiar pantalla.")
        print("6. Salir.")
        opcion = input("Ingresa la opción (número): ")
        if opcion == "1":
            # Lógica para ver los hashes del archivo
            print("EJEMPLO -> /home/user/Escritorio/archivo.pdf")
            file_path = input("Ingresa la ruta del archivo: ")
            hashes = calcular_hash(file_path)
            if hashes:
                print("\n---------------------------Hashes del archivo---------------------------\n")
                for hash_name, hash_value in hashes.items():
                    print(f"{hash_name}: {hash_value}")
                print("\n")
            else:
                print("No se pudo calcular el hash del archivo.")
        elif opcion == "2":
            # Lógica para ver integridad del archivo
            print("EJEMPLO -> /home/user/Escritorio/archivo.pdf")
            file_path = input("Ingresa la ruta del archivo: ")
            if validar_integridad(file_path):
                print("\nEL ARCHIVO ES ÍNTEGRO.\n")
            else:
                print("\nEL ARCHIVO HA SIDO CORROMPIDO.\n")
        elif opcion == "3":
            # Lógica para comparar SHA256 y SHA512
            try:
                print("EJEMPLO -> /home/user/Escritorio/archivo.pdf")
                file_path = input("Ingresa la ruta del archivo: ")
                sha256_hash = input("Ingresa el hash SHA256 del archivo: ")
                sha512_hash = input("Ingresa el hash SHA512 del archivo: ")
                if validar_integridad2(file_path, sha256_hash, sha512_hash):
                    print("\nEL ARCHIVO ES AUTÉNTICO.\n")
                else:
                    print("\nEl ARCHIVO HA SIDO MODIFICADO.\n")
            except ValueError as e:
                print(f"Error: {str(e)}")
            except Exception as e:
                print(f"Error inesperado: {str(e)}")
        elif opcion == "4":
            # Lógica para ver los hashes del archivo
            print("EJEMPLO -> /home/user/Escritorio/archivo.pdf")
            file_path = input("Ingresa la ruta del archivo: ")
            hashes = calcular_hash(file_path)
            if hashes:
                print("\n------------------------Hashes del archivo------------------------\n")
                for hash_name, hash_value in hashes.items():
                    print(f"{hash_name}: {hash_value}")
                print("\n")
            else:
                print("No se pudo calcular el hash del archivo.")
            if validar_integridad(file_path):
                print("EL ARCHIVO ES ÍNTEGRO.\n")
            else:
                print("EL ARCHIVO HA SIDO CORROMPIDO.\n")
        elif opcion == "5":
            clear_console()
        elif opcion == "6":
            break
        else:
            print("Opción inválida. Ingresa una opción válida del menú.")
            
if __name__ == "__main__":
    start()
