from scapy.all import *
import random
import time

# Función para generar un carácter aleatorio (minúscula del alfabeto inglés)
def random_char():
    return chr(random.randint(97, 122))

# Función para construir el payload del paquete
def build_payload(character):
    # Los dos primeros caracteres aleatorios (minúsculas)
    before = random_char()
    after = random_char()
    
    # El mensaje a enviar está en el medio
    data = before + character + after
    
    # El patrón fijo que debe ir después del carácter
    padding = b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" \
              b" !"b"#$%&'()*+,-./01234567"
    
    # Concatenamos los dos componentes
    payload = data.encode() + padding
    return payload

# Función principal para enviar los paquetes ICMP
def send_message(message):
    # Definir la dirección IP de destino
    destination_ip = "8.8.8.8"
    
    # Inicializar el identificador (ID) constante para todos los paquetes ICMP
    icmp_id = random.randint(1, 65535)
    
    # Iniciar la secuencia de los paquetes
    sequence = 1
    
    # Recorrer cada carácter del mensaje
    for char in message:
        # Crear el paquete ICMP tipo Echo Request (tipo 8)
        payload = build_payload(char)
        
        # Crear el paquete ICMP
        packet = IP(dst=destination_ip) / ICMP(type=8, id=icmp_id, seq=sequence) / payload
        
        # Enviar el paquete
        send(packet, verbose=False)
        
        # Incrementar la secuencia para el siguiente paquete
        sequence += 1
        
        # Esperar un poco entre paquetes para evitar sobrecargar la red
        time.sleep(0.1)
        print(f"Enviado paquete con el carácter: {char}")
        
# Pedir al usuario que ingrese el mensaje a enviar
if __name__ == "__main__":
    message = input("Ingresa el mensaje a enviar: ")
    send_message(message)
