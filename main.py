import streamlit as st
import pandas as pd
import string
import random
import hashlib
import base64
 

st.title(" Calculadora Criptografica ")

def explicacion_codigo(texto_codigo, texto_explicacion):
    with st.expander("Explicacion de codigo / funciones"):
        st.code(texto_codigo, line_numbers=True)
        st.markdown(texto_explicacion)

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
    original_a = a  # Guarda una copia de 'a' para devolverla al final
    while b:
        a, b = b, a % b
    return a, original_a // a  # Devuelve el MCD y el valor del MCD

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
def vernam_cifrar_opc_2_2(mensaje, clave):
    mensaje_cifrado = ""
    
    for i in range(len(mensaje)):
        # Obtén el carácter del mensaje y el carácter de la clave en sus respectivas posiciones
        caracter_mensaje = mensaje[i]
        caracter_clave = clave[i % len(clave)]  # Reutiliza la clave ciclicamente
        
        # Aplica la operación XOR entre los caracteres
        resultado_xor = ord(caracter_mensaje) ^ ord(caracter_clave)
        
        # Convierte el resultado de la operación XOR a un carácter imprimible
        caracter_cifrado = chr(resultado_xor)
        
        mensaje_cifrado += caracter_cifrado
    
    return mensaje_cifrado

def vernam_descifrar_opc_2_2(mensaje_cifrado, clave):
    mensaje_descifrado = ""
    
    for i in range(len(mensaje_cifrado)):
        # Obtén el carácter del mensaje cifrado y el carácter de la clave en sus respectivas posiciones
        caracter_cifrado = mensaje_cifrado[i]
        caracter_clave = clave[i % len(clave)]  # Reutiliza la clave ciclicamente
        
        # Aplica la operación XOR entre los caracteres
        resultado_xor = ord(caracter_cifrado) ^ ord(caracter_clave)
        
        # Convierte el resultado de la operación XOR a un carácter imprimible
        caracter_descifrado = chr(resultado_xor)
        
        mensaje_descifrado += caracter_descifrado
    
    return mensaje_descifrado


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
def es_primo(num):
    if num <= 1:
        return False
    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            return False
    return True

# Función para calcular el máximo común divisor (MCD) de dos números
def mcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Función para calcular el inverso multiplicativo modular
def inverso_multiplicativo(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('El inverso multiplicativo no existe')
    return x % m

# Algoritmo extendido de Euclides para calcular el inverso multiplicativo
def extended_gcd(a, b):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0
    

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
        explicacion_codigo(
        '''
        def xor_inverso_opc_1_1(valor, clave):
            resultado_xor = valor ^ clave  # Aplicar XOR
            resultado_inverso = resultado_xor ^ clave  # Aplicar XOR nuevamente
            return resultado_xor, resultado_inverso
        ''', 
        
        '''
        * Toma dos argumentos de entrada: valor y clave. Estos son números enteros que se utilizarán en las operaciones XOR. 
        * Realiza la primera operación XOR entre valor y clave y almacena el resultado en la variable resultado_xor.Esto significa que toma cada bit de valor y lo combina con el bit correspondiente de clave usando la operación XOR, lo que resulta en un nuevo valor. 
        * Luego, realiza una segunda operación XOR entre resultado_xor y clave y almacena el resultado en la variable resultado_inverso. Esto es similar a la primera operación XOR, pero esta vez utiliza el resultado de la primera operación XOR en lugar del valor original valor. 
        * Finalmente, la función devuelve una tupla que contiene dos valores: resultado_xor y resultado_inverso.
        ''')
        valor_original = st.number_input('Escribe el texto en claro', value=583)
        clave_secreta = st.number_input('Escribe la clave', value=251)
        texto_cifrado, texto_claro = xor_inverso_opc_1_1(valor_original, clave_secreta)
        st.write(f'Texto Cifrado:', texto_cifrado)
        st.write(f'Texto Claro:', texto_claro)
        
    elif opciones_1_1 == '1.4 Calcular máximo común divisor (MCD)  e indicar si existe el inverso multiplicativo':
        st.divider()
        st.subheader('Maximo Comun Divisor')
        explicacion_codigo(
        '''
        def calcular_mcd_opc_1_1(a, b):
            original_a = a  # Guarda una copia de 'a' para devolverla al final
            while b:
                a, b = b, a % b
            return a, original_a // a  # Devuelve el MCD y el valor del MCD
        ''', 
        
        '''
        * La función calcular_mcd_opc_1_1 toma dos argumentos, a y b, que representan los dos números enteros de los cuales se calculará el MCD.
        * Dentro del bucle while, a se actualiza con el valor de b, y b se actualiza con el residuo de la división de a entre b. Esto se hace en cada iteración del bucle hasta que b se vuelva cero. En este punto, a contendrá el MCD de los números originales a y original_a.
        * Finalmente, la función devuelve dos valores: el MCD calculado (a) y el valor original de a dividido por el MCD. La división original_a // a se realiza para obtener el valor del MCD en caso de que el usuario desee conocer también la fracción reducida de a entre el MCD.
        ''')
        a = st.number_input('Escribe un numero', value=15)
        b = st.number_input('Escribe un numero', value=49)
        resuldado_1, resuldado_2 = calcular_mcd_opc_1_1(a,b)
        st.write(f'El inverso multiplicativo es: ', resuldado_1)
        if resuldado_1 == 1:
            st.write("El inverso multiplicativo existe")
        else:
            st.write("El inverso multiplicativo no existe")
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
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * euclides_extendido_opc_1_1(a, b): Esta función implementa el algoritmo extendido de Euclides para calcular el máximo común divisor (MCD) extendido de dos números enteros a y b. Devuelve el MCD, así como los coeficientes s y t que satisfacen la ecuación as + bt = MCD. También registra una tabla que muestra los valores de las variables en cada paso del algoritmo.
        * inverso_multiplicativo_opc_1_1(a, m): Esta función utiliza el resultado del algoritmo extendido de Euclides para calcular el inverso multiplicativo de un número a en el campo modular m. Primero, llama a euclides_extendido_opc_1_1 para obtener el MCD y los coeficientes x e y. Si el MCD no es igual a 1, significa que el inverso multiplicativo no existe, por lo que devuelve None. Si x es negativo, lo ajusta para asegurarse de que sea positivo. Luego, devuelve el inverso multiplicativo x y la tabla que se creó durante el proceso.
        ''')
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
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * texto_a_numeros_opc_2_2(texto): Esta función toma un texto como entrada y lo convierte en una lista de números enteros. Asocia cada letra mayúscula y el espacio en blanco a un número en base a su posición en el alfabeto (A=0, B=1, ..., Z=25, espacio=26). Los caracteres que no son letras mayúsculas o espacios se ignoran.
        
        * numeros_a_texto_opc_2_2(numeros): Esta función toma una lista de números enteros y la convierte de nuevo en un texto, utilizando la correspondencia inversa del alfabeto. Cada número se traduce en el carácter correspondiente en el alfabeto.
        * cifrar_mensaje_opc_2_2(mensaje, clave): Esta función cifra un mensaje utilizando una clave. Primero, convierte el mensaje y la clave en listas de números utilizando texto_a_numeros_opc_2_2. Luego, realiza una operación de cifrado sumando los números del mensaje y los números de la clave en una operación módulo 27 (para permitir espacios). El resultado es una lista de números cifrados que se convierten de nuevo en texto utilizando numeros_a_texto_opc_2_2.
        * descifrar_mensaje_opc_2_2(mensaje_cifrado, clave): Esta función descifra un mensaje cifrado utilizando una clave. Al igual que en el proceso de cifrado, convierte el mensaje cifrado y la clave en listas de números y realiza una operación de descifrado restando los números de la clave de los números del mensaje cifrado en una operación módulo 27. El resultado es una lista de números descifrados que se convierten de nuevo en texto utilizando numeros_a_texto_opc_2_2
        ''')
        mensaje_original = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave = st.text_input('Escribe una clave', 'KEY ')
        mensaje_cifrado = cifrar_mensaje_opc_2_2(mensaje_original, clave)
        st.write("Mensaje cifrado:", mensaje_cifrado)
        mensaje_descifrado = descifrar_mensaje_opc_2_2(mensaje_cifrado, clave)
        st.write("Mensaje descifrado:", mensaje_descifrado)
    
    elif opciones_2_2 == '2.2 cifrado cesar':
        st.divider()
        st.subheader('Cifrado Cesar')
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * cifrado_cesar_opc_2_2(texto, desplazamiento): Esta función toma un texto y un valor de desplazamiento como entrada y cifra el texto utilizando el cifrado César con el desplazamiento especificado. El cifrado César desplaza cada letra del alfabeto por un número fijo de posiciones hacia adelante o hacia atrás.
            * La función itera a través de cada carácter en el texto.
            * Verifica si el carácter es una letra utilizando caracter.isalpha().
            * Si el carácter es una letra, determina si es mayúscula o minúscula y lo convierte a mayúscula.
            * Luego, calcula el nuevo carácter cifrado aplicando el desplazamiento en el alfabeto y usando las funciones ord() y chr() para convertir entre caracteres y valores numéricos en el alfabeto.
            * Si el carácter original era minúscula, el carácter cifrado se convierte de nuevo a minúscula.
            * El carácter cifrado se agrega al texto cifrado resultante.
            * Finalmente, la función devuelve el texto cifrado.
            
        * descifrado_cesar_opc_2_2(texto_cifrado, desplazamiento): Esta función toma un texto cifrado y un valor de desplazamiento como entrada y realiza el proceso inverso al cifrado César para descifrar el texto. Esencialmente, llama a la función cifrado_cesar_opc_2_2 con un desplazamiento negativo para revertir el cifrado.
        ''')
        texto_original = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        desplazamiento = st.number_input('Ingresa el desplazamiento', value=3)
        texto_cifrado = cifrado_cesar_opc_2_2(texto_original, desplazamiento)
        st.write("Texto cifrado:", texto_cifrado)
        texto_descifrado = descifrado_cesar_opc_2_2(texto_cifrado, desplazamiento)
        st.write("Texto descifrado:", texto_descifrado)
        
    elif opciones_2_2 == '2.3 cifrado vernam':
        st.divider()
        st.subheader('Cifrado Vernam')
        explicacion_codigo(
        '''
        def vernam_cifrar_opc_2_2(mensaje, clave):
            mensaje_cifrado = ""

            for i in range(len(mensaje)):
                # Obtén el carácter del mensaje y el carácter de la clave en sus respectivas posiciones
                caracter_mensaje = mensaje[i]
                caracter_clave = clave[i % len(clave)]  # Reutiliza la clave ciclicamente

                # Aplica la operación XOR entre los caracteres
                resultado_xor = ord(caracter_mensaje) ^ ord(caracter_clave)

                # Convierte el resultado de la operación XOR a un carácter imprimible
                caracter_cifrado = chr(resultado_xor)

                mensaje_cifrado += caracter_cifrado

            return mensaje_cifrado

        def vernam_descifrar_opc_2_2(mensaje_cifrado, clave):
            mensaje_descifrado = ""

            for i in range(len(mensaje_cifrado)):
                # Obtén el carácter del mensaje cifrado y el carácter de la clave en sus respectivas posiciones
                caracter_cifrado = mensaje_cifrado[i]
                caracter_clave = clave[i % len(clave)]  # Reutiliza la clave ciclicamente

                # Aplica la operación XOR entre los caracteres
                resultado_xor = ord(caracter_cifrado) ^ ord(caracter_clave)

                # Convierte el resultado de la operación XOR a un carácter imprimible
                caracter_descifrado = chr(resultado_xor)

                mensaje_descifrado += caracter_descifrado

            return mensaje_descifrado
        ''', 
        
        '''
        * vernam_cifrar_opc_2_2(mensaje, clave): Esta función toma un mensaje y una clave como entrada y cifra el mensaje utilizando el cifrado Vernam.
            * Itera a través de cada carácter en el mensaje original.
            * Obtiene el carácter correspondiente en la clave utilizando el operador % para reutilizar la clave cíclicamente en caso de que sea más corta que el mensaje.
            * Realiza una operación XOR (bit a bit) entre el valor numérico de los caracteres del mensaje y la clave.
            * Convierte el resultado de la operación XOR nuevamente en un carácter imprimible utilizando chr().
            * Agrega el carácter cifrado al mensaje cifrado resultante.
            
        * vernam_descifrar_opc_2_2(mensaje_cifrado, clave): Esta función toma un mensaje cifrado y una clave como entrada y realiza el proceso inverso para descifrar el mensaje utilizando el cifrado Vernam
            * Similar a la función de cifrado, itera a través de cada carácter en el mensaje cifrado.
            * Obtiene el carácter correspondiente en la clave utilizando el operador %.
            * Realiza una operación XOR entre el valor numérico de los caracteres del mensaje cifrado y la clave.
            * Convierte el resultado de la operación XOR nuevamente en un carácter imprimible utilizando chr().
            * Agrega el carácter descifrado al mensaje descifrado resultante.
        ''')
        texto_original_1 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave_1 = st.text_input('Escribe una clave', 'KEY')
        texto_cifrado_1 = vernam_cifrar_opc_2_2(texto_original_1, clave_1)
        st.write("Texto cifrado:", texto_cifrado_1)
        texto_descifrado_1 = vernam_descifrar_opc_2_2(texto_cifrado_1, clave_1)
        st.write("Texto descifrado:", texto_descifrado_1)
        
    elif opciones_2_2 == '2.4 cifrado ATBASH':
        st.divider()
        st.subheader('Cifrado ATBASH')
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * cifrar_atbash_opc_2_2(texto): Esta función toma un texto como entrada y cifra el texto utilizando el cifrado Atbash.
            * Itera a través de cada carácter en el texto original.
            * Verifica si el carácter es una letra utilizando caracter.isalpha().
            * Si el carácter es una letra, determina si es mayúscula o minúscula y lo convierte a mayúscula.
            * Calcula el valor numérico del carácter original utilizando ord(caracter).
            * Aplica el cifrado Atbash: Si el carácter original está en el rango de 'A' a 'Z', calcula su "opuesto" restando su valor numérico a 'Z' y luego sumando el valor numérico de 'A'. Esto invierte la letra en el alfabeto.
            * Si el carácter original no es una letra (por ejemplo, un espacio o un carácter especial), lo conserva sin cambios.
            * Si el carácter original era minúscula, el carácter cifrado se convierte de nuevo a minúscula.
            * Agrega el carácter cifrado al texto cifrado resultante.
            
        ''')
        texto_original_2 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        texto_cifrado_2 = cifrar_atbash_opc_2_2(texto_original_2)
        st.write("Texto cifrado:", texto_cifrado_2)
        st.write("Texto original:", texto_original_2)
        
    elif opciones_2_2 == '2.5 Cifrador transposición columnar simple':
        st.divider()
        st.subheader('Cifrado de transposicion columnar simple')
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * cifrar_transposicion_columnar_opc_2_2(texto, clave): Esta función toma un texto y una clave como entrada y cifra el texto utilizando el cifrado de transposición columnar.
            * Convierte la clave en una lista de caracteres y la ordena. La clave se utiliza para determinar el orden de las columnas en la matriz.
            * Calcula el número de columnas (num_columnas) como la longitud de la clave.
            * Calcula el número de filas (num_filas) necesario para acomodar todo el texto. Esto se hace dividiendo la longitud del texto entre num_columnas, asegurándose de que la división sea redondeada hacia arriba utilizando la expresión (-(-len(texto) // num_columnas)). Luego, se rellena el texto con espacios en blanco para asegurar que la matriz sea rectangular.
            * Crea una matriz vacía con num_filas filas.
            * Rellena la matriz por columnas. Itera sobre el texto original y coloca cada carácter en la fila adecuada de la matriz según el índice de columna.
            * Lee el texto cifrado por filas en el orden especificado por la clave. Itera sobre las columnas en el orden dado por la clave y luego sobre las filas de la matriz, agregando cada carácter a la cadena de texto cifrado.
            * Finalmente, devuelve el texto cifrado.
            
        ''')
        texto_original_3 = st.text_input('Escribe un mensaje', 'HELLO WORLD')
        clave_3 = st.text_input('Escribe una clave', '1234')
        texto_cifrado_3 = cifrar_transposicion_columnar_opc_2_2(texto_original_3, clave_3)
        st.write("Texto cifrado:", texto_cifrado_3)
        st.write("Texto original:", texto_original_3)
        
    elif opciones_2_2 == '2.6 cifrado afin':
        st.divider()
        st.subheader('Cifrado Afin')
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * cifrar_afin_opc_2_2(texto, a, b): Esta función toma un texto, un valor a, y un valor b como entrada y cifra el texto utilizando el cifrado afín.
            * Define el alfabeto que se utilizará en el cifrado, que en este caso es el alfabeto inglés en mayúsculas.
            * Inicializa una cadena vacía texto_cifrado para almacenar el texto cifrado.
            * Itera a través de cada carácter en el texto original.
            * Verifica si el carácter es una letra utilizando caracter.isalpha().
            * Si el carácter es una letra, determina si es mayúscula y lo convierte a mayúscula.
            * Calcula el valor numérico del carácter en el alfabeto utilizando alfabeto.index(caracter).
            * Aplica el cifrado afín utilizando la fórmula (a * x + b) % m, donde a y b son los valores proporcionados, x es el valor numérico del carácter original, y m es la longitud del alfabeto (en este caso, 26).
            * Convierte el resultado de la operación modular en un carácter correspondiente en el alfabeto.
            * Si el carácter original era minúscula, el carácter cifrado se convierte de nuevo a minúscula.
            * Agrega el carácter cifrado al texto cifrado resultante.
            * Finalmente, devuelve el texto cifrado.
            
        * descifrar_afin_opc_2_2(texto_cifrado, a, b): Esta función toma un texto cifrado, un valor a, y un valor b como entrada y realiza el proceso inverso para descifrar el texto utilizando el cifrado afín.
            * Calcula el inverso multiplicativo de a en el módulo m, que es 26 en este caso. Esto se hace iterando a través de valores de x y buscando un valor a_inverso tal que (a * x) % m == 1.
            * Inicializa una cadena vacía texto_descifrado para almacenar el texto descifrado.
            * Itera a través de cada carácter en el texto cifrado.
            * Verifica si el carácter es una letra utilizando caracter.isalpha().
            * Si el carácter es una letra, determina si es mayúscula y lo convierte a mayúscula.
            * Calcula el valor numérico del carácter en el alfabeto utilizando alfabeto.index(caracter).
            * Aplica la fórmula de descifrado afín utilizando (a_inverso * (y - b)) % m, donde a_inverso es el inverso multiplicativo calculado previamente, y es el valor numérico del carácter cifrado, b es el valor proporcionado, y m es la longitud del alfabeto.
            * Convierte el resultado de la operación modular en un carácter correspondiente en el alfabeto.
            * Si el carácter original era minúscula, el carácter descifrado se convierte de nuevo a minúscula.
            * Agrega el carácter descifrado al texto descifrado resultante.
            * Finalmente, devuelve el texto descifrado.
            
        ''')
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
        explicacion_codigo(
        '''
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
        ''', 
        
        '''
        * cifrar_sustitucion_simple_opc_2_2(texto, clave): Esta función toma un texto y una clave como entrada y cifra el texto utilizando un cifrado de sustitución simple.
            * Define el alfabeto que se utilizará en el cifrado, en este caso, el alfabeto inglés en mayúsculas: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.
            * Inicializa una cadena vacía texto_cifrado para almacenar el texto cifrado.
            * Itera a través de cada carácter en el texto original.
            * Verifica si el carácter es una letra utilizando caracter.isalpha().
            * Determina si el carácter original es mayúscula o minúscula para mantener la capitalización.
            * Verifica si el carácter está en el alfabeto original (mayúsculas). Si no está en el alfabeto, se conserva sin cambios.
            * Si el carácter original está en el alfabeto, encuentra su posición en el alfabeto utilizando alfabeto.index(caracter).
            * Sustituye el carácter original por el carácter correspondiente de la clave proporcionada en esa posición.
            * Si el carácter original era minúscula, el carácter cifrado se convierte de nuevo a minúscula.
            * Agrega el carácter cifrado al texto cifrado resultante.
            * Finalmente, devuelve el texto cifrado.
            
        ''')
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
        explicacion_codigo(
        '''
        def calcular_clave_compartida_opc_3_3(base, modulo, exponente):
            return (base ** exponente) % modulo
        ''', 
        
        '''
        * calcular_clave_compartida_opc_3_3(base, modulo, exponente): Esta función toma tres valores como entrada: base, modulo, y exponente.
            * La base es un número entero que suele ser una clave pública compartida entre dos partes en un protocolo criptográfico.
            * El modulo es otro número entero que se utiliza para realizar la operación modular.
            * El exponente es un número entero que también es proporcionado como entrada.
            * La función realiza la operación de elevar base a la potencia exponente y luego toma el resultado módulo modulo. En otras palabras, calcula (base ** exponente) % modulo.
            * El resultado de esta operación se considera como la clave compartida que se generará y compartirá entre las partes involucradas en el protocolo criptográfico.
            * Finalmente, la función devuelve este valor calculado como la clave compartida.
            
        ''')
        st.caption('Valores compartidos públicamente (normalmente se acuerdan de antemano)')
        modulo_primo = st.number_input('Ingresa el valor de P (cuerpo):', value=1999)
        base = st.number_input('Ingresa el valor del generador α:', value=33)
        
        st.caption('Generar claves privadas aleatorias para ambas partes')
        clave_privada_Phineas = st.number_input('Ingresa el valor de la clave privada de Phineas (a):', value=47)
        clave_privada_Ferb = st.number_input('Ingresa el valor de la clave privada de Ferb (b):', value=117)
        st.write("Se calcula α^a mod p y  α^b mod p")
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
        explicacion_codigo(
        '''
        # Función para verificar si un número es primo
        def es_primo(num):
            if num <= 1:
                return False
            for i in range(2, int(num ** 0.5) + 1):
                if num % i == 0:
                    return False
            return True

        # Función para calcular el máximo común divisor (MCD) de dos números
        def mcd(a, b):
            while b:
                a, b = b, a % b
            return a

        # Función para calcular el inverso multiplicativo modular
        def inverso_multiplicativo(a, m):
            g, x, y = extended_gcd(a, m)
            if g != 1:
                raise Exception('El inverso multiplicativo no existe')
            return x % m

        # Algoritmo extendido de Euclides para calcular el inverso multiplicativo
        def extended_gcd(a, b):
            x0, x1, y0, y1 = 1, 0, 0, 1
            while b:
                q, a, b = a // b, b, a % b
                x0, x1 = x1, x0 - q * x1
                y0, y1 = y1, y0 - q * y1
            return a, x0, y0
        ''', 
        
        '''
        * es_primo(num): Esta función verifica si un número dado num es primo.
            * Comprueba si el número es menor o igual a 1, en cuyo caso se considera que no es primo y devuelve False.
            * Itera desde 2 hasta la raíz cuadrada de num (inclusive).
            * Verifica si num es divisible por alguno de los números en ese rango. Si lo es, devuelve False.
            * Si el bucle termina sin encontrar ningún divisor, devuelve True, lo que indica que num es primo.
            
        * mcd(a, b): Esta función calcula el máximo común divisor (MCD) de dos números a y b utilizando el algoritmo de Euclides.
            * Utiliza un bucle while para aplicar el algoritmo de Euclides: divide a por b y actualiza a y b con los resultados hasta que b se convierte en cero.
            * Devuelve a, que es el MCD de los dos números.
        * inverso_multiplicativo(a, m): Esta función calcula el inverso multiplicativo modular de a en el módulo m.
            * Utiliza la función extended_gcd para encontrar el máximo común divisor (MCD) de a y m, así como los coeficientes de Bézout x e y.
            * Si el MCD no es igual a 1, lo que significa que no existe un inverso multiplicativo modular, se genera una excepción.
            * Si el MCD es igual a 1, calcula el inverso multiplicativo como x % m y lo devuelve.
        * extended_gcd(a, b): Esta función implementa el algoritmo extendido de Euclides para calcular el MCD de a y b junto con los coeficientes de Bézout x e y.
            * Inicializa cuatro variables x0, x1, y0, y y1 para llevar un seguimiento de los coeficientes de Bézout.
            * Utiliza un bucle while para aplicar el algoritmo de Euclides extendido: calcula el cociente q de la división de a entre b y actualiza a y b con los resultados de la división.
            * Actualiza los coeficientes de Bézout x0, x1, y0, y y1 en cada iteración.
            * Finalmente, devuelve el MCD, así como los valores de x0 e y0.
        ''')
        p = st.number_input('Ingresa un numero primo:', value=101)
        q = st.number_input('Ingresa un numero primo:', value=2971)
        mensaje_original = st.number_input('Ingresa un numero para cifrar:', value=1441)
        
        # Verificar si p y q son primos
        if not (es_primo(p) and es_primo(q)):
            raise Exception('Ambos números deben ser primos')

        # Calcular n y phi(n)
        n = p * q
        phi_n = (p - 1) * (q - 1)

        # Elegir un número e coprimo con phi(n)
        e = random.randint(2, phi_n - 1)
        while mcd(e, phi_n) != 1:
            e = random.randint(2, phi_n - 1)

        # Calcular el inverso multiplicativo de e modulo phi(n)
        d = inverso_multiplicativo(e, phi_n)

        # Cifrado
        mensaje_cifrado = pow(mensaje_original, e, n)

        # Descifrado
        mensaje_descifrado = pow(mensaje_cifrado, d, n)
        
        st.caption('Mensajes')
        st.write('Mensaje original: ',mensaje_original)
        st.write('Mensaje cifrado: ',mensaje_cifrado)
        st.write('Mensaje descifrado: ',mensaje_descifrado)
        
    elif opciones_3_3 == '3.3 Calcular Algoritmo de exponenciación rápida':
        st.divider()
        st.subheader('Algoritmo exponenciacion rapida')
        explicacion_codigo(
        '''
        def exponenciacion_rapida_opc_3_3(base, exponente, modulo):
            if exponente == 0:
                return 1
            elif exponente % 2 == 0:
                mitad = exponenciacion_rapida_opc_3_3(base, exponente // 2, modulo)
                return (mitad * mitad) % modulo
            else:
                mitad = exponenciacion_rapida_opc_3_3(base, (exponente - 1) // 2, modulo)
                return (base * mitad * mitad) % modulo
        ''', 
        
        '''
        * exponenciacion_rapida_opc_3_3(base, exponente, modulo): Esta función toma tres valores como entrada: base, exponente, y modulo.

            * Si exponente es igual a 0, la función devuelve 1, ya que cualquier número elevado a la potencia 0 es 1.
            
            * Si exponente es par (es decir, exponente % 2 == 0), la función calcula la mitad del resultado recursivamente llamando a exponenciacion_rapida_opc_3_3 con base, exponente // 2, y modulo. Luego, eleva al cuadrado ese resultado (mitad * mitad) y toma el módulo modulo del resultado.
            * Si exponente es impar, la función calcula la mitad del resultado recursivamente llamando a exponenciacion_rapida_opc_3_3 con base, (exponente - 1) // 2, y modulo. Luego, multiplica base por ese resultado (base * mitad) y eleva al cuadrado ese resultado ((base * mitad) * mitad) y toma el módulo modulo del resultado.
            * La recursión se basa en el principio de dividir y conquistar, donde el exponente se divide en mitades en cada llamada recursiva, lo que reduce significativamente la cantidad de cálculos necesarios.
            * El resultado final es el valor calculado después de todas las llamadas recursivas.
        ''')
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
        explicacion_codigo(
        '''
        def calcular_md5_opc_4_4(cadena):
            # Crear un objeto hash MD5
            md5_hash = hashlib.md5()

            # Actualizar el hash con la cadena
            md5_hash.update(cadena.encode('utf-8'))

            # Obtener el valor hash MD5 en hexadecimal
            hash_resultado = md5_hash.hexdigest()

            return hash_resultado
        ''', 
        
        '''
        * calcular_md5_opc_4_4(cadena): Esta función toma una cadena de texto cadena como entrada y calcula su valor hash MD5.
        
            * Se crea un objeto de hash MD5 utilizando la biblioteca hashlib de Python. Este objeto se llama md5_hash.
            * Se actualiza el objeto de hash md5_hash con la cadena de entrada. Primero, la cadena se codifica como una secuencia de bytes en formato UTF-8 para asegurar que la función de hash funcione correctamente con caracteres especiales y multibyte.
            * Después de actualizar el objeto de hash con la cadena, se obtiene el valor hash MD5 en formato hexadecimal utilizando el método hexdigest() del objeto md5_hash.
            * Finalmente, se devuelve el valor hash MD5 en formato hexadecimal como una cadena de texto.
        ''')
        cadena_md5 = st.text_input('Escribe una cadena para hashear:', 'Lorem ipsum dolor sit amet')
        # Calcular el hash MD5 de la cadena
        resultado_md5 = calcular_md5_opc_4_4(cadena_md5)
        st.write(f'Hash MD5 de la cadena:', resultado_md5)
    
    elif opciones_4_4 == '4.2 Calcular SHA128':
        st.divider()
        st.subheader('Algoritmo SHA-1 o SHA-128')
        explicacion_codigo(
        '''
        def calcular_sha1_opc_4_4(cadena):
            # Crear un objeto hash SHA-1
            sha1_hash = hashlib.sha1()

            # Actualizar el hash con la cadena
            sha1_hash.update(cadena.encode('utf-8'))

            # Obtener el valor hash SHA-1 en hexadecimal
            hash_resultado = sha1_hash.hexdigest()

            return hash_resultado
        ''', 
        
        '''
        * calcular_sha1_opc_4_4(cadena): Esta función toma una cadena de texto cadena como entrada y calcula su valor hash SHA-1.

            * Se crea un objeto de hash SHA-1 utilizando la biblioteca hashlib de Python. Este objeto se llama sha1_hash.
            * Se actualiza el objeto de hash sha1_hash con la cadena de entrada. Primero, la cadena se codifica como una secuencia de bytes en formato UTF-8 para asegurar que la función de hash funcione correctamente con caracteres especiales y multibyte.
            * Después de actualizar el objeto de hash con la cadena, se obtiene el valor hash SHA-1 en formato hexadecimal utilizando el método hexdigest() del objeto sha1_hash.
            * Finalmente, se devuelve el valor hash SHA-1 en formato hexadecimal como una cadena de texto.
        ''')
        cadena_sha1 = st.text_input('Escribe una cadena para hashear:', 'Lorem ipsum dolor sit amet')
        # Calcular el hash MD5 de la cadena
        resultado_sha1 = calcular_sha1_opc_4_4(cadena_sha1)
        st.write(f'Hash MD5 de la cadena:', resultado_sha1)
        
    elif opciones_4_4 == '4.3 Calcular SHA512':
        st.divider()
        st.subheader('Algoritmo SHA-512')
        explicacion_codigo(
        '''
        def calcular_sha512_opc_4_4(cadena):
            # Crear un objeto hash SHA-512
            sha512_hash = hashlib.sha512()

            # Actualizar el hash con la cadena
            sha512_hash.update(cadena.encode('utf-8'))

            # Obtener el valor hash SHA-512 en hexadecimal
            hash_resultado = sha512_hash.hexdigest()

            return hash_resultado
        ''', 
        
        '''
        * calcular_sha512_opc_4_4(cadena): Esta función toma una cadena de texto cadena como entrada y calcula su valor hash SHA-512.

            * Se crea un objeto de hash SHA-512 utilizando la biblioteca hashlib de Python. Este objeto se llama sha512_hash.
            * Se actualiza el objeto de hash sha512_hash con la cadena de entrada. Primero, la cadena se codifica como una secuencia de bytes en formato UTF-8 para asegurar que la función de hash funcione correctamente con caracteres especiales y multibyte.
            * Después de actualizar el objeto de hash con la cadena, se obtiene el valor hash SHA-512 en formato hexadecimal utilizando el método hexdigest() del objeto sha512_hash.
            * Finalmente, se devuelve el valor hash SHA-512 en formato hexadecimal como una cadena de texto.
        ''')
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
        explicacion_codigo(
        '''
        def texto_a_binario_opc_5_5(texto):
            binario = ''.join(format(ord(char), '08b') for char in texto)
            return binario

        def binario_a_texto_opc_5_5(binario):
            texto = ''.join(chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8))
            return texto
        ''', 
        
        '''
        * texto_a_binario_opc_5_5(texto): Esta función toma una cadena de texto texto como entrada y la convierte en su representación binaria.

            * Itera a través de cada carácter en la cadena texto.
            * Para cada carácter, utiliza ord(char) para obtener su valor numérico en el estándar Unicode (el valor numérico del carácter).
            * Luego, usa format(valor, '08b') para convertir ese valor numérico en una cadena binaria de 8 bits (agregando ceros a la izquierda si es necesario para completar los 8 bits).
            * Concatena todas las representaciones binarias de caracteres para formar una cadena binaria completa.
            * Devuelve esta cadena binaria como resultado.

        * binario_a_texto_opc_5_5(binario): Esta función toma una cadena binaria binario como entrada y la convierte en una cadena de texto legible.

            * Divide la cadena binaria en grupos de 8 bits (un byte) utilizando una comprensión de lista y la función range(0, len(binario), 8).
            * Para cada grupo de 8 bits, utiliza int(binario[i:i+8], 2) para convertirlo en un número entero en base 2 (binario).
            * Luego, utiliza chr() para convertir ese número entero en el carácter correspondiente en el estándar Unicode.
            * Concatena todos los caracteres juntos para formar una cadena de texto completa.
            * Devuelve esta cadena de texto como resultado.
        ''')
        texto_codificar = st.text_input('Escribe una cadena para codificar:', 'Lorem ipsum dolor sit amet')
        binario_codificado = texto_a_binario_opc_5_5(texto_codificar)
        st.write('Texto codificado en binario:',binario_codificado)
        
        st.caption('Decodificar en binario')
        texto_decodificar = st.text_input('Pon un codigo binario aqui para decodificar:', '0110010101110011011101000110010100100000011001010111001100100000011101010110111000100000011011010110010101101110011100110110000101101010011001010010000001100101011011100010000001100010011010010110111001100001011100100110100101101111')
        texto_decodificar = texto_decodificar.replace(" ", "")
        # Decodificar binario a texto
        texto_decodificado = binario_a_texto_opc_5_5(texto_decodificar)
        st.write('Texto decodificado en binario: ',texto_decodificado)

    
    elif opciones_5_5 == '3.2 Codificar decodificar hexa':
        st.divider()
        st.subheader('Codificar o Decodificar en hexagesimal')
        explicacion_codigo(
        '''
        texto_codificado_hex = texto_codificar_hexa.encode('utf-8').hex()
        texto_decodificado_hex = bytes.fromhex(texto_codificar_hexa).decode('utf-8')
        ''', 
        
        '''
        * texto_codificado_hex = texto_codificar_hexa.encode('utf-8').hex(): En esta línea, se realiza la codificación de una cadena de texto en formato hexadecimal.

            * texto_codificar_hexa es la cadena de texto que se desea codificar en formato hexadecimal.
            * encode('utf-8') se utiliza para convertir la cadena de texto en una secuencia de bytes utilizando la codificación UTF-8. UTF-8 es una codificación de caracteres ampliamente utilizada que representa los caracteres Unicode en forma de bytes.
            * hex() se utiliza para convertir los bytes resultantes en una cadena de texto hexadecimal. Esto significa que cada byte en la secuencia se representa como dos caracteres hexadecimales en la cadena resultante.
            * El resultado de esta línea, texto_codificado_hex, es una cadena de texto que contiene la representación hexadecimal de la cadena original texto_codificar_hexa.

        * texto_decodificado_hex = bytes.fromhex(texto_codificar_hexa).decode('utf-8'): En esta línea, se realiza la decodificación de una cadena de texto en formato hexadecimal para recuperar la cadena de texto original.

            * texto_codificar_hexa es la cadena de texto hexadecimal que se desea decodificar. 
            * bytes.fromhex(texto_codificar_hexa) se utiliza para convertir la cadena de texto hexadecimal en una secuencia de bytes. Esto revierte la codificación hexadecimal y restaura la representación de bytes original. 
            * decode('utf-8') se utiliza para convertir los bytes resultantes nuevamente en una cadena de texto utilizando la codificación UTF-8. Esto restaura la cadena de texto original a partir de la secuencia de bytes decodificada.
            * El resultado de esta línea, texto_decodificado_hex, es la cadena de texto original que se había codificado previamente en formato hexadecimal.
        ''')
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
        explicacion_codigo(
        '''
        texto_codificado_base64 = base64.b64encode(texto_codificar_base64.encode('utf-8')).decode('utf-8')
        texto_decodificado_base64 = base64.b64decode(texto_decodificar_base64).decode('utf-8')
        ''', 
        
        '''
        * texto_codificado_base64 = base64.b64encode(texto_codificar_base64.encode('utf-8')).decode('utf-8'): En esta línea, se realiza la codificación de la cadena de texto en formato Base64.

            * texto_codificar_base64 es la cadena de texto que se desea codificar en formato Base64.
            * encode('utf-8') se utiliza para convertir la cadena de texto en una secuencia de bytes utilizando la codificación UTF-8, que es una codificación de caracteres ampliamente utilizada. 
            * base64.b64encode(...) se utiliza para codificar los bytes resultantes en formato Base64. Esto convierte la secuencia de bytes en una cadena de texto que contiene caracteres permitidos en el formato Base64. 
            * decode('utf-8') se utiliza para convertir la cadena de texto Base64 resultante en una cadena de texto normal utilizando la codificación UTF-8. Esto es necesario si deseas manipular la cadena codificada en formato Base64 como texto. 
            * El resultado de esta línea, texto_codificado_base64, es la cadena de texto original codificada en formato Base64.

        * texto_decodificado_base64 = base64.b64decode(texto_decodificar_base64).decode('utf-8'): En esta línea, se realiza la decodificación de una cadena de texto en formato Base64 para recuperar la cadena de texto original.

            * texto_decodificar_base64 es la cadena de texto en formato Base64 que se desea decodificar. 
            * base64.b64decode(...) se utiliza para decodificar la cadena de texto Base64 en una secuencia de bytes. Esto revierte la codificación Base64 y restaura la representación de bytes original.
            * decode('utf-8') se utiliza para convertir los bytes resultantes en una cadena de texto utilizando la codificación UTF-8. Esto restaura la cadena de texto original a partir de la secuencia de bytes decodificada. 
            * El resultado de esta línea, texto_decodificado_base64, es la cadena de texto original que se había codificado previamente en formato Base64.
        ''')
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