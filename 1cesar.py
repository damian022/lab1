# Programa de cifrado César en Python 3

def es_texto_valido(texto):
    """
    Verifica si el texto contiene solo letras minúsculas del alfabeto inglés y espacios.
    """
    for caracter in texto:
        if not (caracter.islower() or caracter == ' '):
            return False
    return True

def cifrar_cesar(texto, desplazamiento):
    """
    Cifra el texto utilizando el algoritmo de César con un desplazamiento dado.
    El cifrado es circular sobre el alfabeto.
    """
    resultado = ''
    for caracter in texto:
        if caracter == ' ':
            resultado += ' '
        else:
            # Obtener la posición de la letra en el alfabeto (0 para 'a', 25 para 'z')
            posicion_original = ord(caracter) - ord('a')
            # Aplicar el desplazamiento y envolver con módulo 26
            nueva_posicion = (posicion_original + desplazamiento) % 26
            # Convertir de nuevo a letra
            nueva_letra = chr(nueva_posicion + ord('a'))
            resultado += nueva_letra
    return resultado

def main():
    """
    Función principal del programa. Solicita entradas del usuario,
    valida y muestra el resultado del cifrado.
    """
    texto = input("Introduce el texto a cifrar (solo letras minúsculas y espacios): ")
    
    # Validación del texto
    if not es_texto_valido(texto):
        print("Error: El texto solo puede contener letras del alfabeto inglés en minúsculas y espacios.")
        return

    try:
        desplazamiento = int(input("Introduce el número de desplazamiento (entero positivo): "))
        if desplazamiento < 0:
            print("Error: El desplazamiento debe ser un número entero positivo.")
            return
    except ValueError:
        print("Error: El desplazamiento debe ser un número entero.")
        return

    texto_cifrado = cifrar_cesar(texto, desplazamiento)
    print("Texto cifrado:", texto_cifrado)

# Ejecutar el programa
if __name__ == "__main__":
    main()