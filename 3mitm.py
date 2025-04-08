import pyshark
import string
import nltk
from nltk.corpus import words

# Asegúrate de haber descargado el diccionario de palabras en español
nltk.download('words')

def cargar_diccionario_espanol():
    """
    Carga un diccionario de palabras en español para la evaluación de las secuencias generadas.
    """
    # Lista de palabras en español en minúsculas
    with open('palabras_espanol.txt', 'r', encoding='utf-8') as file:
        return set(word.strip().lower() for word in file.readlines())

def reconstruir_mensaje(pcap_file):
    """
    Procesa un archivo .pcapng, extrae el segundo carácter de los paquetes ICMP de tipo Echo Request
    y reconstruye el mensaje transmitido, generando todas las combinaciones posibles basadas
    en un desplazamiento desconocido.
    """
    # Abrir y analizar el archivo de captura .pcapng
    try:
        captura = pyshark.FileCapture(pcap_file, display_filter="icmp.type == 8")
    except Exception as e:
        print(f"Error al abrir el archivo de captura: {e}")
        return []

    # Extraer los caracteres del segundo campo de data en los paquetes ICMP tipo Echo Request
    caracteres_extraidos = []
    for paquete in captura:
        try:
            # Extraemos el campo "data" del paquete y tomamos el segundo carácter
            data = paquete.icmp.data
            if len(data) > 1:
                caracteres_extraidos.append(data[1])  # Segundo carácter
        except AttributeError:
            # Si el paquete no contiene el campo data, lo ignoramos
            continue

    return caracteres_extraidos

def generar_combinaciones(mensaje):
    """
    Genera todas las combinaciones posibles de un mensaje dado, asumiendo que puede haber un desplazamiento
    desconocido en el texto original.
    """
    # Desplazamientos posibles (de 0 a 25 para las letras)
    combinaciones = []
    for desplazamiento in range(26):
        combinacion = ''.join(
            chr(((ord(c) - ord('a') + desplazamiento) % 26) + ord('a')) if c.islower() else
            chr(((ord(c) - ord('A') + desplazamiento) % 26) + ord('A')) if c.isupper() else c
            for c in mensaje
        )
        combinaciones.append(combinacion)
    return combinaciones

def evaluar_mensaje(mensaje, diccionario):
    """
    Evalúa la probabilidad de que una secuencia de caracteres sea un mensaje válido en español
    basado en la cantidad de palabras válidas encontradas.
    """
    palabras_validas = sum(1 for palabra in mensaje.split() if palabra in diccionario)
    return palabras_validas

def mostrar_resultados(combinaciones, diccionario):
    """
    Muestra todas las combinaciones posibles de mensajes y resalta el más probable
    basándose en la evaluación con el diccionario de palabras en español.
    """
    mejor_combinacion = None
    max_palabras_validas = -1

    for combinacion in combinaciones:
        palabras_validas = evaluar_mensaje(combinacion, diccionario)
        if palabras_validas > max_palabras_validas:
            max_palabras_validas = palabras_validas
            mejor_combinacion = combinacion

    # Imprimir todas las combinaciones generadas
    print("Combinaciones posibles de mensajes:")
    for combinacion in combinaciones:
        if combinacion == mejor_combinacion:
            print(f"\033[92m{combinacion}\033[0m")  # Resalta el mensaje más probable en verde
        else:
            print(combinacion)

def main():
    """
    Función principal que coordina el flujo del programa.
    """
    # Pedir al usuario el nombre del archivo .pcapng
    archivo = input("Introduce el nombre del archivo .pcapng (debe estar en el mismo directorio): ")
    
    # Verificar si el archivo existe y procesarlo
    try:
        caracteres = reconstruir_mensaje(archivo)
        if not caracteres:
            print("No se encontraron paquetes ICMP tipo Echo Request con datos válidos.")
            return

        # Reconstruir el mensaje transmitido (secuencia de caracteres)
        mensaje = ''.join(caracteres)
        print(f"Mensaje reconstruido (sin desplazamiento): {mensaje}")

        # Generar todas las combinaciones posibles del mensaje
        combinaciones = generar_combinaciones(mensaje)

        # Cargar el diccionario en español
        diccionario = cargar_diccionario_espanol()

        # Mostrar los resultados
        mostrar_resultados(combinaciones, diccionario)
    
    except Exception as e:
        print(f"Se produjo un error: {e}")

if __name__ == '__main__':
    main()
