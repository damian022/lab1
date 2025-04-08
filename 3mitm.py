import os
from scapy.all import rdpcap, ICMP
from collections import Counter
from colorama import Fore, Style

def leer_captura(nombre_archivo):
    """Lee un archivo .pcapng y devuelve una lista de paquetes ICMP Echo Request válidos."""
    if not os.path.exists(nombre_archivo):
        raise FileNotFoundError(f"Archivo no encontrado: {nombre_archivo}")
    
    try:
        paquetes = rdpcap(nombre_archivo)
    except Exception as e:
        raise IOError(f"Error al leer el archivo: {e}")
    
    echo_requests = []
    for pkt in paquetes:
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo Request
            raw_data = bytes(pkt[ICMP].payload)
            if len(raw_data) >= 2:
                echo_requests.append(raw_data[1:2].decode(errors='ignore'))  # Segundo carácter
    return echo_requests

def cifrado_cesar(texto, desplazamiento):
    """Aplica un cifrado César inverso (decodificación) con un desplazamiento dado."""
    resultado = ""
    for char in texto:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            resultado += chr((ord(char) - base - desplazamiento) % 26 + base)
        else:
            resultado += char
    return resultado

def generar_combinaciones(texto):
    """Genera 25 combinaciones de cifrado César posibles del texto."""
    return [(i, cifrado_cesar(texto, i)) for i in range(1, 26)]

def puntuacion_vocales(texto):
    """Calcula una puntuación basada en la frecuencia de las vocales en español."""
    texto = texto.lower()
    contador = Counter(texto)
    puntuacion = (
        contador.get('a', 0) * 0.25 +
        contador.get('e', 0) * 0.35 +
        contador.get('o', 0) * 0.2 +
        contador.get('i', 0) * 0.15 +
        contador.get('u', 0) * 0.05
    )
    return puntuacion

def encontrar_mas_probable(combinaciones):
    """Determina la combinación más probable según el análisis de frecuencia de vocales."""
    mejor = max(combinaciones, key=lambda x: puntuacion_vocales(x[1]))
    return mejor

def main():
    print("== Análisis de Captura ICMP - Reconstrucción de Mensaje ==")
    nombre_archivo = input("Ingrese el nombre del archivo .pcapng: ").strip()
    
    try:
        caracteres = leer_captura(nombre_archivo)
        if not caracteres:
            print("No se encontraron paquetes ICMP Echo Request válidos con datos suficientes.")
            return
        mensaje_original = ''.join(caracteres)
        combinaciones = generar_combinaciones(mensaje_original)
        mejor_desplazamiento, mensaje_descifrado = encontrar_mas_probable(combinaciones)
        
        print("\n== Combinaciones posibles (Cifrado César) ==")
        for desplazamiento, texto in combinaciones:
            if desplazamiento == mejor_desplazamiento:
                print(f"{Fore.GREEN}[{desplazamiento}] {texto}{Style.RESET_ALL}")
            else:
                print(f"[{desplazamiento}] {texto}")
        
        print(f"\nMensaje reconstruido: {Fore.GREEN}{mensaje_descifrado}{Style.RESET_ALL}")
        print(f"Desplazamiento utilizado para decodificar: {mejor_desplazamiento}")
        
    except FileNotFoundError as fe:
        print(f"Error: {fe}")
    except IOError as ioe:
        print(f"Error al procesar el archivo: {ioe}")
    except Exception as e:
        print(f"Ocurrió un error inesperado: {e}")

if __name__ == "__main__":
    main()
