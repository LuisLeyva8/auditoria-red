import time
import random
from flask import Flask, jsonify
from flask_cors import CORS
from collections import defaultdict

# IMPORTACIONES NECESARIAS PARA AUDITORÍA REAL
# ¡El código intentará usar Scapy!
try:
    from scapy.all import sniff, IP
    CAN_AUDIT_REAL = True
except ImportError:
    CAN_AUDIT_REAL = False
    print("ADVERTENCIA: Scapy no está instalado. El auditor funcionará en modo de SIMULACIÓN.")
except Exception as e:
    CAN_AUDIT_REAL = False
    print(f"ERROR: No se pudo cargar Scapy. El auditor funcionará en modo de SIMULACIÓN. Error: {e}")

# --- CONFIGURACIÓN DEL SERVIDOR ---
app = Flask(__name__)
# Habilitar CORS para permitir que React (que se ejecuta en un puerto diferente) acceda a esta API.
CORS(app) 

# --- ESTADO SIMULADO/AUDITADO DE LA RED ---
NUM_DEVICES = 8
network_devices = {}
last_update_time = time.time()

# Parámetros de detección (deben coincidir con el frontend)
PACKET_RATE_CHECK_INTERVAL_COUNT = 5
NORMAL_PACKET_MAX = 50 
ATTACK_PACKET_MIN = 800
ATTACK_PACKET_MAX = 1200

def initialize_devices():
    """Inicializa el estado de los dispositivos de la red."""
    global network_devices
    network_devices = {} # Asegurar que esté vacío antes de inicializar
    # Mantener el listado estático de IPs para la demostración
    for i in range(NUM_DEVICES):
        ip = f"192.168.1.{10 + i}"
        device_id = f"USR-PC-{str(i+1).zfill(2)}"
        network_devices[ip] = {
            "id": device_id,
            "ip": ip,
            "packetsSent": 0,
            "status": "Connected",
            "isAttacker": False,
            "packetRateLimit": 5000, # Límite por defecto para la detección de TASA
            "recentPacketHistory": [],
            "dailyAverage": random.randint(1000, 4000)
        }
    # Asignar aleatoriamente un atacante (solo activo si falla la auditoría real)
    attacker_ip = random.choice(list(network_devices.keys()))
    network_devices[attacker_ip]["isAttacker"] = True
    print(f"Dispositivos inicializados. Atacante simulado: {attacker_ip}")

def _simulation_fallback():
    """Función de respaldo que genera datos de paquetes simulados."""
    packet_counts = defaultdict(int)
    
    for ip, device in network_devices.items():
        if device["status"] == "Blocked":
            continue

        if device["isAttacker"]:
            # Simular alto volumen de paquetes para exfiltración (ACTIVO EN SIMULACIÓN)
            packets_sent = random.randint(ATTACK_PACKET_MIN, ATTACK_PACKET_MAX)
        else:
            # Simular tráfico normal de bajo volumen
            packets_sent = random.randint(1, NORMAL_PACKET_MAX)
        
        packet_counts[ip] = packets_sent
        
    return packet_counts

def sniff_and_process_packets():
    """
    Función que ejecuta la captura de paquetes en la red (real) o usa la simulación como fallback.
    Ahora incluye descubrimiento dinámico de dispositivos.
    """
    
    if CAN_AUDIT_REAL:
        # --- CÓDIGO PARA CAPTURA REAL DE PAQUETES ---
        try:
            # Capturar hasta 300 paquetes o timeout después de 1 segundo. Filtra solo tráfico IP.
            # store=0 asegura que los paquetes no se guarden en memoria, mejorando el rendimiento.
            packets = sniff(count=300, timeout=1, filter="ip", store=0) 
            
            packet_counts = defaultdict(int)
            for pkt in packets:
                if IP in pkt:
                    src_ip = pkt[IP].src
                    
                    # 1. Descubrimiento Dinámico: Si la IP de origen no es conocida, la inicializamos.
                    if src_ip not in network_devices:
                        # Añadir la nueva IP al diccionario de seguimiento.
                        network_devices[src_ip] = {
                            "id": f"DYN-DEV-{src_ip.split('.')[-1]}", # ID dinámico basado en el último octeto
                            "ip": src_ip,
                            "packetsSent": 0,
                            "status": "Connected",
                            "isAttacker": False,
                            "packetRateLimit": 5000,
                            "recentPacketHistory": [],
                            "dailyAverage": random.randint(1000, 4000)
                        }
                        print(f"DEBUG: Nuevo dispositivo descubierto: {src_ip}")

                    # 2. Contar paquetes para el dispositivo (ya sea estático o dinámico)
                    packet_counts[src_ip] += 1
            return packet_counts
            
        except Exception as e:
            # Falla de permisos (la causa más común sin sudo)
            print(f"ADVERTENCIA: Falló la captura de red. ¿Ejecutando con sudo? Usando simulación. Error: {e}")
            return _simulation_fallback()
    else:
        # --- SIMULACIÓN DE PAQUETES (Fallback) ---
        return _simulation_fallback()

def update_network_status():
    """
    Actualiza el estado de la red leyendo el conteo de paquetes capturados
    y aplica la lógica de detección de tasa.
    """
    global network_devices, last_update_time
    
    if not network_devices:
        initialize_devices()

    # 1. Obtener el conteo de paquetes del auditor (real o simulado)
    packet_counts_this_turn = sniff_and_process_packets() 
    
    # Prepara una lista de IPs a verificar para evitar modificar el diccionario mientras se itera sobre él
    ips_to_check = list(network_devices.keys()) 

    for ip in ips_to_check:
        if ip not in network_devices: # Podría ser un dispositivo que se añadió en sniff_and_process_packets
             continue

        device = network_devices[ip]

        if device["status"] == "Blocked":
            continue
            
        # packets_sent_this_turn se obtiene del auditor real/simulado
        packets_sent_this_turn = packet_counts_this_turn.get(ip, 0)
        
        # 1. Actualizar el total y el historial
        device["packetsSent"] += packets_sent_this_turn
        device["recentPacketHistory"].append(packets_sent_this_turn)
        
        # Mantener solo el tamaño de la ventana de detección
        while len(device["recentPacketHistory"]) > PACKET_RATE_CHECK_INTERVAL_COUNT:
            device["recentPacketHistory"].pop(0)

        # 2. Lógica de Detección por Tasa
        recent_packet_sum = sum(device["recentPacketHistory"])
        
        # Si la suma reciente excede el límite Y tenemos suficientes datos en la ventana
        if recent_packet_sum > device["packetRateLimit"] and len(device["recentPacketHistory"]) == PACKET_RATE_CHECK_INTERVAL_COUNT:
            # Aquí, solo establecemos el estado de ALERTA para que React lo maneje.
            device["status"] = "ALERT" 
        elif device["status"] == "ALERT" and recent_packet_sum <= device["packetRateLimit"]:
             device["status"] = "Connected"
        
    last_update_time = time.time()

@app.route('/api/network_status', methods=['GET'])
def network_status():
    """Endpoint para que React obtenga el estado actual de la red."""
    # Simular un ciclo de auditoría antes de responder
    update_network_status()
    
    # Devolver una lista de dispositivos (más fácil de manejar en React)
    return jsonify(list(network_devices.values()))

@app.route('/api/reset', methods=['POST'])
def reset_network():
    """Endpoint para resetear el estado de la simulación."""
    initialize_devices()
    return jsonify({"message": "Estado de red reseteado."})

@app.route('/api/device/<ip>/<action>', methods=['POST'])
def device_control(ip, action):
    """Endpoint para bloquear/desbloquear dispositivos o cambiar el límite."""
    if ip not in network_devices:
        return jsonify({"error": "Dispositivo no encontrado"}), 404

    device = network_devices[ip]
    if action == 'block':
        device['status'] = 'Blocked'
        # NOTA: En la vida real, aquí se ejecutaría un comando para el firewall/switch (iptables, etc.)
        return jsonify({"message": f"Dispositivo {ip} bloqueado."})
    elif action == 'unblock':
        device['status'] = 'Connected'
        return jsonify({"message": f"Dispositivo {ip} desbloqueado."})

    return jsonify({"error": "Acción inválida"}), 400

if __name__ == '__main__':
    initialize_devices()
    print("Iniciando servidor Flask en http://127.0.0.1:5000...")
    if not CAN_AUDIT_REAL:
        print("*************************************************************************************")
        print("* ADVERTENCIA CRÍTICA: Scapy no está disponible. Ejecutando en MODO SIMULACIÓN. *")
        print("* Instala 'scapy' y usa 'sudo python network_server.py' para la auditoría real. *")
        print("*************************************************************************************")
    app.run(debug=True, port=5000)
