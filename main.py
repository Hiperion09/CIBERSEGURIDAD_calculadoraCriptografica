import streamlit as st
import pandas as pd
import string
import random
import hashlib
import base64

st.title(" Calculadora Criptografica ")

def calcular_modulo_opc_1_1(a, b):
    if b == 0:
        st.write('El modulo no puede ser cero!!!!')
    modulo = a % b
    return modulo

def inverso_aditivo_modulo_opc_1_1(numero, modulo):
    inverso = -numero
    inverso_modulo = inverso % modulo
    return inverso_modulo

def xor_inverso_opc_1_1(valor, clave):
    resultado_xor = valor ^ clave  # Aplicar XOR
    resultado_inverso = resultado_xor ^ clave  # Aplicar XOR nuevamente
    return resultado_xor, resultado_inverso

def calcular_mcd_opc_1_1(a, b):
    while b:
        a, b = b, a % b
    return a

def euclides_extendido_opc_1_1(a, b):
    tabla = []
    
    # Inicialización de variables
    r0, r1 = a, b
    s0, s1 = 1, 0
    t0, t1 = 0, 1
    
    tabla.append(("i", "gi", "yi", "ui", "vi"))
    tabla.append((0, r0, "-", s0, t0))
    tabla.append((1, r1, "-", s1, t1))
    
    i = 2
    
    while r1 != 0:
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        
        # Intercambia si y ti
        s0, s1 = s1, s0 - q * s1
        t0, t1 = t1, t0 - q * t1
        
        tabla.append((i, r1, q, s1, t1))
        i += 1
    
    return r0, s0, t0, tabla

def inverso_multiplicativo_opc_1_1(a, m):
    gcd, x, y, tabla = euclides_extendido_opc_1_1(a, m)
    if gcd != 1:
        return None  # No tiene inverso multiplicativo
    if x < 0:
        x += m
    return x, tabla


# Algoritmos de criptografia clasica
# ---------------   Cifrado modulo 27   ---------------------------
def texto_a_numeros_opc_2_2(texto):
    alfabeto = string.ascii_uppercase + ' '
    texto = texto.upper()
    numeros = []
    for caracter in texto:
        if caracter in alfabeto:
            numero = alfabeto.index(caracter)
            numeros.append(numero)
    return numeros

def numeros_a_texto_opc_2_2(numeros):
    alfabeto = string.ascii_uppercase + ' '
    texto = ''
    for numero in numeros:
        if 0 <= numero < len(alfabeto):
            caracter = alfabeto[numero]
            texto += caracter
    return texto

def cifrar_mensaje_opc_2_2(mensaje, clave):
    numeros_mensaje = texto_a_numeros_opc_2_2(mensaje)
    numeros_clave = texto_a_numeros_opc_2_2(clave)
    
    mensaje_cifrado = []
    for i in range(len(numeros_mensaje)):
        mensaje_cifrado.append((numeros_mensaje[i] + numeros_clave[i % len(numeros_clave)]) % 27)
    
    return numeros_a_texto_opc_2_2(mensaje_cifrado)

def descifrar_mensaje_opc_2_2(mensaje_cifrado, clave):
    numeros_cifrado = texto_a_numeros_opc_2_2(mensaje_cifrado)
    numeros_clave = texto_a_numeros_opc_2_2(clave)
    
    mensaje_descifrado = []
    for i in range(len(numeros_cifrado)):
        mensaje_descifrado.append((numeros_cifrado[i] - numeros_clave[i % len(numeros_clave)]) % 27)
    
    return numeros_a_texto_opc_2_2(mensaje_descifrado)


# ---------------   Cifrado cesar   ---------------------------
def cifrado_cesar_opc_2_2(texto, desplazamiento):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():  # Verifica si el caracter es una letra
            mayuscula = caracter.isupper()  # Verifica si es mayúscula o minúscula
            caracter = caracter.upper()
            codigo = ord(caracter) - ord('A')
            codigo = (codigo + desplazamiento) % 26
            caracter_cifrado = chr(codigo + ord('A'))
            if not mayuscula:
                caracter_cifrado = caracter_cifrado.lower()
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter  # Conserva caracteres no alfabéticos
    return texto_cifrado
def descifrado_cesar_opc_2_2(texto_cifrado, desplazamiento):
    return cifrado_cesar_opc_2_2(texto_cifrado, -desplazamiento)

# ---------------   Cifrado vernam   ---------------------------
def generar_clave_vernam_opc_2_2(longitud):
    clave = []
    for _ in range(longitud):
        clave.append(random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
    return ''.join(clave)

def cifrar_vernam_opc_2_2(texto, clave):
    texto_cifrado = []
    for i in range(len(texto)):
        char_texto = texto[i]
        char_clave = clave[i]
        # Realiza la operación XOR para cifrar
        char_cifrado = chr(ord(char_texto) ^ ord(char_clave))
        texto_cifrado.append(char_cifrado)
    return ''.join(texto_cifrado)

def descifrar_vernam_opc_2_2(texto_cifrado, clave):
    return cifrar_vernam_opc_2_2(texto_cifrado, clave)  # El cifrado Vernam es su propio descifrado
# ---------------   Cifrado atbash   ---------------------------
def cifrar_atbash_opc_2_2(texto):
    texto_cifrado = ""
    for caracter in texto:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.upper()
            codigo = ord(caracter)
            # Aplicar el cifrado Atbash
            if codigo >= ord('A') and codigo <= ord('Z'):
                caracter_cifrado = chr(ord('Z') - (codigo - ord('A')))
            else:
                caracter_cifrado = caracter
            if not mayuscula:
                caracter_cifrado = caracter_cifrado.lower()
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter
    return texto_cifrado
# ---------------   Cifrado transposicion columnar simple   ---------------------------
def cifrar_transposicion_columnar_opc_2_2(texto, clave):
    clave = list(clave)
    clave.sort()  # Ordenar la clave para determinar el orden de las columnas
    
    num_columnas = len(clave)
    num_filas = -(-len(texto) // num_columnas)  # Calcular el número de filas (división redondeada hacia arriba)
    
    # Rellenar con espacios en blanco si es necesario
    texto += ' ' * (num_filas * num_columnas - len(texto))
    
    matriz = [[] for _ in range(num_filas)]
    
    # Rellenar la matriz por columnas
    for i, caracter in enumerate(texto):
        fila = i // num_columnas
        matriz[fila].append(caracter)
    
    # Leer el texto cifrado por filas en el orden de la clave
    texto_cifrado = ''
    for col in clave:
        col_index = clave.index(col)
        for fila in matriz:
            if col_index < len(fila):
                texto_cifrado += fila[col_index]
    
    return texto_cifrado
# ---------------   Cifrado afin   ---------------------------
def cifrar_afin_opc_2_2(texto, a, b):
    alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    m = len(alfabeto)
    
    texto_cifrado = ''
    for caracter in texto:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.upper()
            x = alfabeto.index(caracter)
            x_cifrado = (a * x + b) % m
            caracter_cifrado = alfabeto[x_cifrado]
            if not mayuscula:
                caracter_cifrado = caracter_cifrado.lower()
            texto_cifrado += caracter_cifrado
        else:
            texto_cifrado += caracter
    
    return texto_cifrado

def descifrar_afin_opc_2_2(texto_cifrado, a, b):
    m = 26  # Tamaño del alfabeto inglés
    
    # Calcular el inverso multiplicativo de 'a' en m
    for x in range(1, m):
        if (a * x) % m == 1:
            a_inverso = x
            break
    
    alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    texto_descifrado = ''
    for caracter in texto_cifrado:
        if caracter.isalpha():
            mayuscula = caracter.isupper()
            caracter = caracter.upper()
            y = alfabeto.index(caracter)
            y_descifrado = (a_inverso * (y - b)) % m
            caracter_descifrado = alfabeto[y_descifrado]
            if not mayuscula:
                caracter_descifrado = caracter_descifrado.lower()
            texto_descifrado += caracter_descifrado
        else:
            texto_descifrado += caracter
    
    return texto_descifrado
# ---------------   Cifrado de sustitucion simple   ---------------------------
def cifrar_sustitucion_simple_opc_2_2(texto, clave):
    alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    texto_cifrado = ''

    for caracter in texto:
        if caracter.isalpha():  # Verifica si el caracter es una letra
            mayuscula = caracter.isupper()  # Verifica si es mayúscula o minúscula
            caracter = caracter.upper()
            
            if caracter in alfabeto:
                indice_original = alfabeto.index(caracter)
                caracter_cifrado = clave[indice_original]
                
                if not mayuscula:
                    caracter_cifrado = caracter_cifrado.lower()
                
                texto_cifrado += caracter_cifrado
            else:
                texto_cifrado += caracter
        else:
            texto_cifrado += caracter
    
    return texto_cifrado

# Algoritmos de criptografia moderna

# ---------------   Diffie hellman  ---------------------------
def calcular_clave_compartida_opc_3_3(base, modulo, exponente):
    return (base ** exponente) % modulo



# ---------------   RSA  ---------------------------
# Función para verificar si un número es primo
def es_primo_opc_3_3(numero):
    if numero <= 1:
        return False
    if numero <= 3:
        return True
    if numero % 2 == 0 or numero % 3 == 0:
        return False
    i = 5
    while i * i <= numero:
        if numero % i == 0 or numero % (i + 2) == 0:
            return False
        i += 6
    return True

# Función para encontrar el máximo común divisor (MCD) usando el algoritmo de Euclides extendido
def encontrar_mcdRSA_opc_3_3(a, b):
    if b == 0:
        return a
    else:
        return encontrar_mcdRSA_opc_3_3(b, a % b)

# Función para encontrar el inverso modular usando el algoritmo de Euclides extendido
def encontrar_inverso_modularRSA_opc_3_3(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0

# Función para generar un par de claves RSA
def generar_clavesRSA_opc_3_3():
    # Elegir dos números primos grandes
    p = 101
    q = 2971
    while not (es_primo_opc_3_3(p) and es_primo_opc_3_3(q)):
        p = random.randint(100, 1000)
        q = random.randint(100, 1000)

    # Calcular n (el producto de p y q)
    n = p * q

    # Calcular la función phi de Euler (φ(n))
    phi = (p - 1) * (q - 1)

    # Elegir un número entero e que sea coprimo con φ(n)
    e = random.randint(2, phi - 1)
    while encontrar_mcdRSA_opc_3_3(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Calcular el inverso modular de e
    d = encontrar_inverso_modularRSA_opc_3_3(e, phi)

    # Clave pública (e, n) y clave privada (d, n)
    clave_publica = (e, n)
    clave_privada = (d, n)

    return clave_publica, clave_privada

# Función para cifrar un mensaje (texto o número) usando la clave pública
def cifrarRSA_opc_3_3(mensaje, clave_publica):
    e, n = clave_publica
    if isinstance(mensaje, int):
        mensaje_cifrado = pow(mensaje, e, n)
    elif isinstance(mensaje, str):
        mensaje_cifrado = [pow(ord(char), e, n) for char in mensaje]
    else:
        raise ValueError("El mensaje debe ser un entero o una cadena de texto")
    return mensaje_cifrado

# Función para descifrar un mensaje cifrado usando la clave privada
def descifrarRSA_opc_3_3(mensaje_cifrado, clave_privada):
    d, n = clave_privada
    if isinstance(mensaje_cifrado, int):
        mensaje_descifrado = pow(mensaje_cifrado, d, n)
    elif isinstance(mensaje_cifrado, list):
        mensaje_descifrado = [chr(pow(char, d, n)) for char in mensaje_cifrado]
        mensaje_descifrado = ''.join(mensaje_descifrado)
    else:
        raise ValueError("El mensaje cifrado debe ser un entero o una lista de enteros")
    return mensaje_descifrado
    

# ---------------   Exponenciacion rapida  ---------------------------
def exponenciacion_rapida_opc_3_3(base, exponente, modulo):
    if exponente == 0:
        return 1
    elif exponente % 2 == 0:
        mitad = exponenciacion_rapida_opc_3_3(base, exponente // 2, modulo)
        return (mitad * mitad) % modulo
    else:
        mitad = exponenciacion_rapida_opc_3_3(base, (exponente - 1) // 2, modulo)
        return (base * mitad * mitad) % modulo
    

# Algoritmos HASH
# ---------------   Algoritmo MD5  ---------------------------
def calcular_md5_opc_4_4(cadena):
    # Crear un objeto hash MD5
    md5_hash = hashlib.md5()

    # Actualizar el hash con la cadena
    md5_hash.update(cadena.encode('utf-8'))

    # Obtener el valor hash MD5 en hexadecimal
    hash_resultado = md5_hash.hexdigest()

    return hash_resultado

# ---------------   Algoritmo SHA-1  ---------------------------
# Función para calcular el hash SHA-1 de una cadena
def calcular_sha1_opc_4_4(cadena):
    # Crear un objeto hash SHA-1
    sha1_hash = hashlib.sha1()

    # Actualizar el hash con la cadena
    sha1_hash.update(cadena.encode('utf-8'))

    # Obtener el valor hash SHA-1 en hexadecimal
    hash_resultado = sha1_hash.hexdigest()

    return hash_resultado


# ---------------   Algoritmo SHA-512  ---------------------------
# Función para calcular el hash SHA-512 de una cadena
def calcular_sha512_opc_4_4(cadena):
    # Crear un objeto hash SHA-512
    sha512_hash = hashlib.sha512()

    # Actualizar el hash con la cadena
    sha512_hash.update(cadena.encode('utf-8'))

    # Obtener el valor hash SHA-512 en hexadecimal
    hash_resultado = sha512_hash.hexdigest()

    return hash_resultado


# Algoritmos de codificacion
# ---------------   Algoritmo binario  ---------------------------
def texto_a_binario_opc_5_5(texto):
    binario = ''.join(format(ord(char), '08b') for char in texto)
    return binario

def binario_a_texto_opc_5_5(binario):
    texto = ''.join(chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8))
    return texto


opciones_1 = st.selectbox(
    'Selecciona alguna tematica',
    ('1. Operaciones matematicas modulares', '2. Criptografia Clasica', '3. Criptografia Moderna', '4. Algoritmos Hash', '5. Codificación'))

if opciones_1 == '1. Operaciones matematicas modulares':
    st.header('SUBMENU MATEMATICA MODULAR')
    dicccionario_opc_1 = {
        1: '1.1 Calcular el módulo de dos números a mod n = b',
        2: '1.2 Calcular inverso aditivo',
        3: '1.3 Calcular inverso de XOR',
        4: '1.4 Calcular máximo común divisor (MCD)  e indicar si existe el inverso multiplicativo',
        5: '1.5 Calcular inverso multiplicativo por metodo tradicional visto en clase',
        6: '1.6 Calcular el  inverso multiplicativo aplicando el Algoritmo Extendido de Euclides AEE, indicando cuantas rondas, y mostrar tabla'
    }
    opciones_1_1 = st.radio("Selecciona una opcion", dicccionario_opc_1.values())
    
    if opciones_1_1 == '1.1 Calcular el módulo de dos números a mod n = b':
        st.divider()
        st.subheader('Modulo entre dos numeros')
        a = st.number_input('Escribe un numero (a)', value=198)
        n = st.number_input('Escribe un numero (n)', value=27)
        resultado = calcular_modulo_opc_1_1(a,n)
        st.write('El modulo del numero es ', resultado)
        
    elif opciones_1_1 == '1.2 Calcular inverso aditivo':
        st.divider()
        st.subheader('Inverso Aditivo')
        a = st.number_input('Escribe un numero (a)', value=198)
        n = st.number_input('Escribe un numero (n)', value=27)
        st.write(f'El inverso aditivo es de {a} en modulo {n} es ', inverso_aditivo_modulo_opc_1_1(a,n))
        
    elif opciones_1_1 == '1.3 Calcular inverso de XOR':
        st.divider()
        st.subheader('Inverso XOR')
        valor_original = st.number_input('Escribe el texto en claro', value=583)
        clave_secreta = st.number_input('Escribe la clave', value=251)
        texto_cifrado, texto_claro = xor_inverso_opc_1_1(valor_original, clave_secreta)
        st.write(f'Texto Cifrado:', texto_cifrado)
        st.write(f'Texto Claro:', texto_claro)
        
    elif opciones_1_1 == '1.4 Calcular máximo común divisor (MCD)  e indicar si existe el inverso multiplicativo':
        st.divider()
        st.subheader('Maximo Comun Divisor')
        a = st.number_input('Escribe un numero', value=15)
        b = st.number_input('Escribe un numero', value=49)
        resuldado_1 = calcular_mcd_opc_1_1(a,b)
        if resuldado_1 == 1:
            st.write(f'El inverso multiplicativo existe entre {a} y {b}')
        else:
            st.write(f'El inverso multiplicativo no existe entre {a} y {b}')
        
    elif opciones_1_1 == '1.5 Calcular inverso multiplicativo por metodo tradicional visto en clase':
        st.divider()
        st.subheader('Metodo tradicional Inverso Multiplicativo')
        n = st.number_input('Escribe un numero:', value=28)
        m = st.number_input('Escribe un cuerpo:', value=135)
        with st.expander("Comprobacion con multiplicacion con los restos"):
            for i in range(m):
                val = n*i%m
                st.write(f'{n}*{i} mod {m} = {val}')
                if val == 1:
                    mensaje = f'El inverso multiplicativo de {n} en cuerpo {m} es {i}'
                    break
                else:
                    mensaje = f'No exite el inverso multiplicativo de {n} en cuerpo {m}'
        st.write(mensaje)
        
    elif opciones_1_1 == '1.6 Calcular el  inverso multiplicativo aplicando el Algoritmo Extendido de Euclides AEE, indicando cuantas rondas, y mostrar tabla':
        st.divider()
        st.subheader('Inverso multiplicativo aplicando AEE')
        valor_1 = st.number_input('Escribe un numero', value=15)
        valor_2 = st.number_input('Escribe un numero', value=49)
        inverso, tabla = inverso_multiplicativo_opc_1_1(valor_1, valor_2)
        if inverso is not None:
            st.write(f"El inverso multiplicativo de {valor_1} modulo {valor_2} es", inverso)
            # Crear un DataFrame a partir de la tabla
            df = pd.DataFrame(tabla[1:], columns=tabla[0])
            # Intercambiar el orden de las columnas "si" y "ti"
            df = df[['i', 'yi', 'gi', 'vi', 'ui']]
            st.subheader("Tabla")
            st.dataframe(df)
        else:
            st.write(f"No existe inverso multiplicativo de {valor_1} modulo {valor_2}")
        
elif opciones_1 == '2. Criptografia Clasica':
    st.subheader('SUBMENU CRIPTOGRAFIA CLASICA')
    dicccionario_opc_2 = {
        1: '2.1 cifrado Módulo 27',
        2: '2.2 cifrado cesar',
        3: '2.3 cifrado vernam',
        4: '2.4 cifrado ATBASH',
        5: '2.5 Cifrador transposición columnar simple',
        6: '2.6 cifrado afin',
        7: '2.7 Cifra de Sustitución Simple',
    }
    opciones_2_2 = st.radio("Selecciona una opcion", dicccionario_opc_2.values())
    
    if opciones_2_2 == '2.1 cifrado Módulo 27':
        st.divider()
        st.subheader('Cifrado en modulo 27')
        mensaje_original = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave = st.text_input('Escribe una clave', 'KEY ')
        mensaje_cifrado = cifrar_mensaje_opc_2_2(mensaje_original, clave)
        st.write("Mensaje cifrado:", mensaje_cifrado)
        mensaje_descifrado = descifrar_mensaje_opc_2_2(mensaje_cifrado, clave)
        st.write("Mensaje descifrado:", mensaje_descifrado)
    
    elif opciones_2_2 == '2.2 cifrado cesar':
        st.divider()
        st.subheader('Cifrado Cesar')
        texto_original = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        desplazamiento = st.number_input('Ingresa el desplazamiento', value=3)
        texto_cifrado = cifrado_cesar_opc_2_2(texto_original, desplazamiento)
        st.write("Texto cifrado:", texto_cifrado)
        texto_descifrado = descifrado_cesar_opc_2_2(texto_cifrado, desplazamiento)
        st.write("Texto descifrado:", texto_descifrado)
        
    elif opciones_2_2 == '2.3 cifrado vernam':
        st.divider()
        st.subheader('Cifrado Vernam')
        texto_original_1 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave_1 = generar_clave_vernam_opc_2_2(len(texto_original_1))
        texto_cifrado_1 = cifrar_vernam_opc_2_2(texto_original_1, clave_1)
        st.write("Texto cifrado:", texto_cifrado_1)
        texto_descifrado_1 = descifrar_vernam_opc_2_2(texto_cifrado_1, clave_1)
        st.write("Texto descifrado:", texto_descifrado_1)
        
    elif opciones_2_2 == '2.4 cifrado ATBASH':
        st.divider()
        st.subheader('Cifrado ATBASH')
        texto_original_2 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        texto_cifrado_2 = cifrar_atbash_opc_2_2(texto_original_2)
        st.write("Texto cifrado:", texto_cifrado_2)
        st.write("Texto original:", texto_original_2)
        
    elif opciones_2_2 == '2.5 Cifrador transposición columnar simple':
        st.divider()
        st.subheader('Cifrado de transposicion columnar simple')
        texto_original_3 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave_3 = st.text_input('Escribe una clave', '1234')
        texto_cifrado_3 = cifrar_transposicion_columnar_opc_2_2(texto_original_3, clave_3)
        st.write("Texto cifrado:", texto_cifrado_3)
        st.write("Texto original:", texto_original_3)
        
    elif opciones_2_2 == '2.6 cifrado afin':
        st.divider()
        st.subheader('Cifrado Afin')
        texto_original_4 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        coef_a = st.number_input('coeficiente de transformacion a', value=5)
        coef_b = st.number_input('coeficiente de transformacion b', value=8)
        texto_cifrado_4 = cifrar_afin_opc_2_2(texto_original_4, coef_a, coef_b)
        texto_descifrado_4 = descifrar_afin_opc_2_2(texto_cifrado_4, coef_a, coef_b)
        st.write("Texto cifrado:", texto_cifrado_4)
        st.write("Texto descifrado:", texto_descifrado_4)
        
    elif opciones_2_2 == '2.7 Cifra de Sustitución Simple':
        st.divider()
        st.subheader('Cifrado de sustitucion simple')
        texto_original_5 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave_4 = st.text_input('Escribe una clave', 'NOPQRSTUVWXYZABCDEFGHIJKLM')
        texto_cifrado_4 = cifrar_sustitucion_simple_opc_2_2(texto_original_5, clave_4)
        st.write("Texto cifrado:", texto_cifrado_4)
        st.write("Texto descifrado:", texto_original_5)
        
elif opciones_1 == '3. Criptografia Moderna':
    st.subheader('SUBMENU CRIPTOGRAFIA MODERNA')
    dicccionario_opc_3 = {
        1: '3.1 Calcular Diffie Hellman',
        2: '3.2 Calcular RSA',
        3: '3.3 Calcular Algoritmo de exponenciación rápida'
    }
    opciones_3_3 = st.radio("Selecciona una opcion", dicccionario_opc_3.values())
    
    if opciones_3_3 == '3.1 Calcular Diffie Hellman':
        st.divider()
        st.subheader('Algoritmo de Diffie Hellman')
        
        st.caption('Valores compartidos públicamente (normalmente se acuerdan de antemano)')
        modulo_primo = st.number_input('Ingresa el valor de P (Modulo):', value=1999)
        base = st.number_input('Ingresa el valor del generador α:', value=33)
        
        st.caption('Generar claves privadas aleatorias para ambas partes')
        clave_privada_Phineas = st.number_input('Ingresa el valor de la clave privada de Phineas:', value=47)
        clave_privada_Ferb = st.number_input('Ingresa el valor de la clave privada de Ferb:', value=117)
        
        # Calcular las claves públicas de ambas partes
        clave_publica_Phineas = calcular_clave_compartida_opc_3_3(base, modulo_primo, clave_privada_Phineas)
        clave_publica_Ferb = calcular_clave_compartida_opc_3_3(base, modulo_primo, clave_privada_Ferb)

        # Intercambio de claves públicas (puede ser a través de un canal inseguro)
        clave_compartida_Phineas = calcular_clave_compartida_opc_3_3(clave_publica_Ferb, modulo_primo, clave_privada_Phineas)
        clave_compartida_Ferb = calcular_clave_compartida_opc_3_3(clave_publica_Phineas, modulo_primo, clave_privada_Ferb)
        
        st.write("Clave compartida en el lado de Phineas", clave_compartida_Phineas)
        st.write("Clave compartida en el lado de Ferb", clave_compartida_Ferb)
    
    elif opciones_3_3 == '3.2 Calcular RSA':
        st.divider()
        st.subheader('Algoritmo RSA')
        msj_numero_1 = st.number_input('Ingresa un numero:', value=1441)
        msj_texto_1 = st.text_input('Escribe un mensaje secreto', 'Hola, este es un mensaje secreto')
        
        # Generar un par de claves RSA
        clave_publica, clave_privada = generar_clavesRSA_opc_3_3()
        
        # Cifrar y descifrar texto
        mensaje_cifrado_texto = cifrarRSA_opc_3_3(msj_texto_1, clave_publica)
        mensaje_descifrado_texto = descifrarRSA_opc_3_3(mensaje_cifrado_texto, clave_privada)
        
        # Cifrar y descifrar números
        mensaje_cifrado_numero = cifrarRSA_opc_3_3(msj_numero_1, clave_publica)
        mensaje_descifrado_numero = descifrarRSA_opc_3_3(mensaje_cifrado_numero, clave_privada)
        
        st.caption('Claves')
        st.write('Clave publica: ',clave_publica)
        st.write('Clave privada: ',clave_privada)
        
        st.caption('Mensaje secreto texto')
        st.write('Mensaje original: ',msj_texto_1)
        st.write('Mensaje cifrado: ',mensaje_cifrado_texto)
        st.write('Mensaje descifrado: ',mensaje_descifrado_texto)
        
        st.caption('Mensaje secreto numero')
        st.write('Mensaje original: ',msj_numero_1)
        st.write('Mensaje cifrado: ',mensaje_cifrado_numero)
        st.write('Mensaje descifrado: ',mensaje_descifrado_numero)
        
    elif opciones_3_3 == '3.3 Calcular Algoritmo de exponenciación rápida':
        st.divider()
        st.subheader('Algoritmo exponenciacion rapida')
        clave = st.number_input('Ingresa un numero para la clave:', value=53972)
        texto = st.number_input('Ingresa un numero para el texto:', value=753)
        cuerpo = st.number_input('Ingresa un numero para el cuerpo:', value=3655147)
        resultado = exponenciacion_rapida_opc_3_3(clave, texto, cuerpo)
        st.write(f'Resultado:', resultado)
        
elif opciones_1 == '4. Algoritmos Hash':
    st.subheader('ALGORITMOS HASH')
    dicccionario_opc_4 = {
        1: '4,1 Calcular md5',
        2: '4.2 Calcular SHA128',
        3: '4.3 Calcular SHA512'
    }
    opciones_4_4 = st.radio("Selecciona una opcion", dicccionario_opc_4.values())
    
    if opciones_4_4 == '4,1 Calcular md5':
        st.divider()
        st.subheader('Algoritmo MD5')
        cadena_md5 = st.text_input('Escribe una cadena para hashear:', 'Lorem ipsum dolor sit amet')
        # Calcular el hash MD5 de la cadena
        resultado_md5 = calcular_md5_opc_4_4(cadena_md5)
        st.write(f'Hash MD5 de la cadena:', resultado_md5)
    
    elif opciones_4_4 == '4.2 Calcular SHA128':
        st.divider()
        st.subheader('Algoritmo SHA-1 o SHA-128')
        cadena_sha1 = st.text_input('Escribe una cadena para hashear:', 'Lorem ipsum dolor sit amet')
        # Calcular el hash MD5 de la cadena
        resultado_sha1 = calcular_sha1_opc_4_4(cadena_sha1)
        st.write(f'Hash MD5 de la cadena:', resultado_sha1)
        
    elif opciones_4_4 == '4.3 Calcular SHA512':
        st.divider()
        st.subheader('Algoritmo SHA-512')
        cadena_sha512 = st.text_input('Escribe una cadena para hashear:', 'Lorem ipsum dolor sit amet')
        # Calcular el hash MD5 de la cadena
        resultado_sha512 = calcular_sha512_opc_4_4(cadena_sha512)
        st.write(f'Hash SHA-512 de la cadena:', resultado_sha512)
        

elif opciones_1 == '5. Codificación':
    st.subheader('CODIFICACION')
    dicccionario_opc_5 = {
        1: '3.1 Codificar decodificar binario',
        2: '3.2 Codificar decodificar hexa',
        3: '3.3 Codificar decodificar base64'
    }
    opciones_5_5 = st.radio("Selecciona una opcion", dicccionario_opc_5.values())
    
    if opciones_5_5 == '3.1 Codificar decodificar binario':
        st.divider()
        st.subheader('Codificar o Decodificar en binario')
        
        st.caption('Codificacion en binario')
        texto_codificar = st.text_input('Escribe una cadena para codificar:', 'Lorem ipsum dolor sit amet')
        binario_codificado = texto_a_binario_opc_5_5(texto_codificar)
        st.write('Texto codificado en binario:',binario_codificado)
        
        st.caption('Decodificar en binario')
        texto_decodificar = st.text_input('Pon un codigo binario aqui para decodificar:', '0110010101110011011101000110010100100000011001010111001100100000011101010110111000100000011011010110010101101110011100110110000101101010011001010010000001100101011011100010000001100010011010010110111001100001011100100110100101101111')
        texto_decodificar = texto_decodificar.replace(" ", "")
        # Decodificar binario a texto
        texto_decodificado = binario_a_texto_opc_5_5(texto_decodificar)
        st.write('Texto decodificado en binario',texto_decodificado)

    
    elif opciones_5_5 == '3.2 Codificar decodificar hexa':
        st.divider()
        st.subheader('Codificar o Decodificar en hexagesimal')
        
        st.caption('Codificacion en hexagesimal')
        # Codificar texto a hexadecimal
        texto_codificar_hexa = st.text_input('Escribe una cadena para codificar:', 'Lorem ipsum dolor sit amet')
        texto_codificado_hex = texto_codificar_hexa.encode('utf-8').hex()
        # Mostrar el texto codificado en hexadecimal
        st.write("Texto codificado en hexadecimal:", texto_codificado_hex)

        st.caption('Decodificacion en hexagesimal')
        # Decodificar hexadecimal a texto
        texto_codificar_hexa = st.text_input('Escribe un hexagesimal para decodificar:', f'{texto_codificado_hex}')
        texto_decodificado_hex = bytes.fromhex(texto_codificar_hexa).decode('utf-8')
        # Mostrar el texto decodificado
        st.write("Texto decodificado:", texto_decodificado_hex)
    elif opciones_5_5 == '3.3 Codificar decodificar base64':
        st.divider()
        st.subheader('Codificar o Decodificar en base64')
        
        st.caption('Codificacion en base64')
        # Codificar texto a hexadecimal
        texto_codificar_base64 = st.text_input('Escribe una cadena para codificar:', 'Lorem ipsum dolor sit amet')
        texto_codificado_base64 = base64.b64encode(texto_codificar_base64.encode('utf-8')).decode('utf-8')
        # Mostrar el texto codificado en hexadecimal
        st.write("Texto codificado en hexadecimal:", texto_codificado_base64)
        
        st.caption('Decodificacion en base64')
        # Codificar texto a hexadecimal
        texto_decodificar_base64 = st.text_input('Escribe una cadena para decodificar:', 'bWVuc2FqZSBzZWNyZXRv')
        # Decodificar Base64 a texto
        texto_decodificado_base64 = base64.b64decode(texto_decodificar_base64).decode('utf-8')
        # Mostrar el texto codificado en hexadecimal
        st.write("Texto decodificado en base64:", texto_decodificado_base64)