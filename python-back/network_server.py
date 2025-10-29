# -*- coding: utf-8 -*-
import time
from threading import Lock, Thread

from flask import Flask, jsonify, request
from flask_cors import CORS

# --- CONFIGURACIÓN DE SCAPY ---
try:
    # AÑADIDO: Raw para inspección del contenido del paquete (carga útil)
    # AÑADIDO: Ether para obtener la MAC Address (Capa 2)
    from scapy.all import IP, TCP, UDP, conf, sniff, Raw, Ether 

    # ¡MODIFICACIÓN!
    # En lugar de forzar 'enp4s0', dejamos que Scapy detecte la interfaz
    # de enrutamiento principal. Esto es mucho más fiable.
    ACTIVE_INTERFACE = conf.iface

    if not ACTIVE_INTERFACE:
        # Si Scapy no puede encontrar una, lanzamos un error claro.
        raise Exception(
            "Scapy no pudo detectar una interfaz de red activa (conf.iface está vacío)."
        )

    print(
        f"INFO: Scapy cargado exitosamente. Interfaz activa detectada: {ACTIVE_INTERFACE}"
    )

except ImportError as e:
    raise ImportError(
        "ERROR CRÍTICO: No se pudo cargar Scapy. Instala Scapy y/o las dependencias de libpcap."
    ) from e
except Exception as e:
    # Error de inicialización (ej. permisos de socket o la detección de arriba).
    raise Exception(
        f"ERROR CRÍTICO: Fallo al inicializar Scapy. Asegúrate de ejecutar con 'sudo'. Error: {e}"
    ) from e


# --- NUEVA FUNCIÓN: Fingerprinting de SO (Basado en TTL) ---
def get_os_fingerprint(ttl):
    """Estima el Sistema Operativo basado en el valor inicial de TTL."""
    # Los TTL de los sistemas operativos comunes tienden a empezar en: 64 (Linux/Unix), 128 (Windows).
    # Buscamos la "clase" de TTL más cercana, sabiendo que disminuye con los saltos.
    if 50 <= ttl <= 70:
        return "Linux/Unix (TTL ~64)"
    elif 110 <= ttl <= 135:
        return "Windows (TTL ~128)"
    elif 240 <= ttl <= 255:
        return "Antiguo/IoT (TTL ~255)"
    else:
        return "Desconocido/Router"

# --- NUEVO: Simulación de Búsqueda de Fabricante por OUI ---
# NOTA: En un sistema real, usarías la librería 'mac-vendor-lookup' 
OUI_MAPPING = {
    "90:3A:D9": "Apple, Inc. (iPhone/Mac)",
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "00:00:0C": "Cisco Systems",
    "A4:7B:2D": "Samsung",
    "C8:3E:99": "Dell",
}

def get_manufacturer(mac):
    """Simula la búsqueda del fabricante por OUI (primeros 3 octetos de la MAC)."""
    if mac and mac != "00:00:00:00:00:00":
        oui = mac[:8].upper() # Formato XX:XX:XX
        return OUI_MAPPING.get(oui, "Fabricante Desconocido")
    return "N/A"
# -----------------------------------------------------------


# --- NUEVO: Simulación de Tipos de Dispositivo ---
# Asignación basada en el último octeto de la IP (solo para demostrar la funcionalidad)
DEVICE_TYPES_MAP = {
    # ip.split('.')[-1] % 4 (0=PC, 1=Mobile, 2=Server, 3=IOT/TV)
    0: "PC/Laptop",
    1: "Móvil/Tablet",
    2: "Servidor",
    3: "Doméstico/IoT (TV, etc.)",
}

# --- CONFIGURACIÓN DE AUDITORÍA ---
# Unidades: Paquetes
DETECTION_WINDOW_SIZE = 5  # Número de ciclos para medir la tasa de paquetes.
DEFAULT_PACKET_LIMIT = 1500  # Límite de paquetes acumulados en la ventana de tiempo para activar la alerta.
SNIFF_TIMEOUT_S = 3  # Duración de cada ciclo de captura de Scapy

# Estado Global de la Red
network_devices = {}
lock = Lock()
is_sniffing_running = False


def initialize_devices():
    """Inicializa la estructura de datos para la auditoría."""
    global network_devices
    # Los dispositivos se añadirán dinámicamente al capturar paquetes.
    network_devices = {}
    print("Estado de dispositivos reseteado. Esperando tráfico en la red...")


# --- FUNCIÓN: Extracción de Dominio (Existente) ---
def extract_domain(pkt):
    """Extrae el dominio para tráfico HTTP (Port 80) o marca HTTPS/Otros."""
    if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and Raw in pkt:
        try:
            payload = pkt[Raw].load.decode('utf-8', 'ignore')
            for line in payload.split('\r\n'):
                if line.lower().startswith('host:'):
                    return line.split(': ')[1].strip()
        except Exception:
            return "HTTP (Error Decodificando)"

    if TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
        return "HTTPS (Dominio Cifrado)"
    
    if UDP in pkt and (pkt[UDP].dport == 53 or pkt[UDP].sport == 53):
        return "DNS (Nombre Cifrado)"
    
    return "N/A o Protocolo No Web"


# --- LÓGICA DE CAPTURA DE RED (SCAPY) EN HILO SEPARADO ---


def packet_callback(pkt):
    """Función de callback de Scapy: se llama para cada paquete capturado."""
    global network_devices

    # Solo procesamos paquetes IP con capa de origen y Ethernet para la MAC/Longitud.
    if IP in pkt and hasattr(pkt[IP], "src") and Ether in pkt:
        src_ip = pkt[IP].src
        src_mac = pkt[Ether].src 
        packet_length = len(pkt) # Longitud del paquete en bytes
        
        # --- Extracción de Huella de SO ---
        os_fingerprint = get_os_fingerprint(pkt[IP].ttl) 
        # ----------------------------------

        # --- Extracción del Dominio (Existente) ---
        domain = extract_domain(pkt)
        # -----------------------------

        # --- Extracción del Fabricante (NUEVO) ---
        manufacturer = get_manufacturer(src_mac)
        # -----------------------------

        with lock:
            # --- Extracción de información detallada (existente) ---
            protocol = (
                "ICMP"
                if pkt.haslayer("ICMP")
                else (
                    "TCP"
                    if pkt.haslayer(TCP)
                    else ("UDP" if pkt.haslayer(UDP) else "Otros")
                )
            )

            dst_port = ""
            if TCP in pkt:
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                dst_port = pkt[UDP].dport

            # 1. Incorporar nuevos dispositivos encontrados
            if src_ip not in network_devices:
                # --- ASIGNACIÓN DE TIPO DE DISPOSITIVO (SIMULADA) ---
                try:
                    octet = int(src_ip.split('.')[-1])
                    device_type = DEVICE_TYPES_MAP[octet % len(DEVICE_TYPES_MAP)]
                except ValueError:
                    device_type = DEVICE_TYPES_MAP[0] # Fallback
                # -----------------------------------------------------------

                network_devices[src_ip] = {
                    # La IP 127.0.0.1 se maneja para evitar spam de localhost
                    "id": f"HOST-{src_ip.split('.')[-1]}"
                    if src_ip != "127.0.0.1"
                    else "LOCALHOST (127.0.0.1)",
                    "ip": src_ip,
                    "macAddress": src_mac,     
                    "manufacturer": manufacturer, 
                    "os_fingerprint": os_fingerprint,     
                    "status": "Connected",
                    "packetCount": 0,
                    "recentPacketHistory": [],
                    "bandwidthHistoryTotal": 0,          
                    "recentBandwidthRate": [],           
                    "packetLimit": DEFAULT_PACKET_LIMIT,
                    "last_protocol": protocol,
                    "last_port": dst_port,
                    "is_local": src_ip.startswith("192.168.")
                    or src_ip.startswith("10.")
                    or src_ip.startswith("172."),
                    "deviceType": device_type,
                    "last_visited_domain": domain, 
                    "packetLengthThisCycle": [], # Inicialización correcta para dispositivos nuevos
                }
            
            # 2. Solo contar si el dispositivo no está bloqueado
            device = network_devices[src_ip]
            
            # FIX DEFENSA DENTRO DEL CALLBACK: Si un dispositivo existente no tiene el campo, inicializarlo.
            if "packetLengthThisCycle" not in device:
                device["packetLengthThisCycle"] = []
                
            if device["status"] != "Blocked":
                device["packetCount"] += 1
                device["last_protocol"] = protocol
                device["last_port"] = dst_port
                
                # Actualizar metadatos
                if device["os_fingerprint"] in ["Desconocido/Router", "Linux/Unix (TTL ~64)"]: 
                     device["os_fingerprint"] = os_fingerprint
                if device["macAddress"] == "00:00:00:00:00:00" or device["manufacturer"] == "N/A":
                     device["macAddress"] = src_mac
                     device["manufacturer"] = manufacturer
                     
                # NUEVO: Sumar bytes al total
                device["bandwidthHistoryTotal"] += packet_length
                
                # NUEVO: Añadir longitud del paquete a un historial temporal
                device["packetLengthThisCycle"].append(packet_length) 

                # --- ACTUALIZAR DOMINIO SOLO SI ES TRÁFICO WEB (No N/A) ---
                if domain not in ["N/A o Protocolo No Web", "DNS (Nombre Cifrado)"]:
                    device["last_visited_domain"] = domain
                # ---------------------------------------------------------


def start_continuous_sniffing():
    """Inicia el bucle de captura de Scapy en un hilo dedicado."""
    global is_sniffing_running

    if is_sniffing_running:
        return

    def sniffing_loop():
        global is_sniffing_running
        is_sniffing_running = True
        print(
            f"INFO: Hilo de auditoría real iniciado en {ACTIVE_INTERFACE}. Capturando tráfico IP..."
        )

        while is_sniffing_running:
            # Antes de empezar un ciclo, preparamos para acumular bytes del ciclo actual.
            with lock:
                for device in network_devices.values():
                    # FIX DEFENSA ANTES DE RESET: Inicializa el campo si no existe (para dispositivos antiguos)
                    if "packetLengthThisCycle" not in device:
                        device["packetLengthThisCycle"] = []

                    # Inicializar/Resetear el acumulador de bytes del ciclo actual
                    device["packetLengthThisCycle"] = [] 

            try:
                print("DEBUG: Entrando al bloque sniff() de Scapy...") # <-- NUEVO DEBUG PRINT
                # Captura de paquetes IP (L3). Llama a packet_callback.
                packets = sniff(
                    prn=packet_callback,
                    filter="ip", 
                    iface=ACTIVE_INTERFACE,
                    timeout=SNIFF_TIMEOUT_S,
                )

                if len(packets) == 0:
                    print(
                        f"DEBUG: 0 paquetes capturados en el ciclo de {SNIFF_TIMEOUT_S}s."
                    )

            except Exception as e:
                # FIX: Se incluye la variable e en el print para visibilidad
                print(
                    f"ERROR CRÍTICO en hilo de Scapy. Deteniendo auditoría de red: {e} (Tipo: {type(e)})" # <-- MEJORA LOGGING
                )
                is_sniffing_running = False  # Detener el hilo si falla
                break
                
            # Después del sniffing, calculamos la tasa
            with lock:
                for device in network_devices.values():
                    # Añadir defensa para campos nuevos por si fallan en el reinicio
                    if "recentBandwidthRate" not in device: device["recentBandwidthRate"] = []
                    if "recentPacketHistory" not in device: device["recentPacketHistory"] = []

                    if device["status"] != "Blocked":
                        # NUEVO: Sumar el total de bytes capturados en ESTE ciclo
                        # La defensa se hizo antes, así que este campo existe
                        bytes_sent_this_cycle = sum(device["packetLengthThisCycle"])
                        
                        # 2. Registrar solo ciclos con tráfico para la detección de tasa
                        if bytes_sent_this_cycle > 0:
                            # Tasa de Paquetes (Existente)
                            packets_sent_this_cycle = len(device["packetLengthThisCycle"])
                            device["recentPacketHistory"].append(packets_sent_this_cycle)
                            
                            # Tasa de Ancho de Banda (NUEVO)
                            device["recentBandwidthRate"].append(bytes_sent_this_cycle)
                        
                        # 3. Mantener el historial solo dentro de la ventana de detección
                        if len(device["recentPacketHistory"]) > DETECTION_WINDOW_SIZE:
                            device["recentPacketHistory"].pop(0)
                        if len(device["recentBandwidthRate"]) > DETECTION_WINDOW_SIZE:
                            device["recentBandwidthRate"].pop(0)

            # Pequeña pausa
            time.sleep(0.1)
        print("INFO: Hilo de auditoría real detenido.")

    # Iniciar el hilo y hacerlo un demonio
    thread = Thread(target=sniffing_loop)
    thread.daemon = True
    thread.start()
    
    # NUEVO DEBUG: Esperar un momento para que el hilo falle y el error se imprima
    time.sleep(1) 
    
    # NUEVO DEBUG: Comprobar el estado del hilo justo después de la espera
    if not thread.is_alive():
        print("ALERTA: El hilo de auditoría falló inmediatamente después de iniciar. El error DEBE estar arriba.")


# --- LÓGICA DE DETECCIÓN Y REPORTE (LLAMADA POR EL FRONTEND) ---


def update_network_status():
    """Ejecuta la detección de tasa y formatea la respuesta basada en datos reales."""
    global network_devices

    if not is_sniffing_running:
        # Si el hilo de sniffing falló o no se inició, no tenemos datos.
        raise Exception(
            "El hilo de auditoría real no está activo. Verifique los logs de error."
        )

    with lock:
        # Procesar el tráfico y aplicar la detección
        for ip, device in list(network_devices.items()):
            if device["status"] == "Blocked":
                continue

            # --- DETECCIÓN POR TASA DE PAQUETES (Existente) ---
            
            # 4. Detección por Tasa de Paquetes
            # Añadir defensa para campos nuevos en el bucle principal (para un reinicio limpio)
            if "recentPacketHistory" not in device: device["recentPacketHistory"] = []

            current_rate = sum(device["recentPacketHistory"])

            if current_rate > device["packetLimit"]:
                # ¡DETECCIÓN DE DESVÍO POR TASA RÁPIDA!
                device["status"] = "Blocked"
                device["recentPacketHistory"] = []  # Limpiar historial
                # Añadir defensa para campos nuevos
                if "recentBandwidthRate" in device: device["recentBandwidthRate"] = []  

                print(
                    f"[CRÍTICO] BLOQUEADO: {ip}. Paquetes en ventana exceden límite: {current_rate} > {device['packetLimit']}"
                )

    # Formatear la respuesta para el frontend
    device_list = list(network_devices.values())

    # El status ahora es simple
    status = {
        "isRunning": True,
        "simulating": False,  # Siempre Falso
    }

    return device_list, status


# --- CONFIGURACIÓN DE FLASK ---

app = Flask(__name__)
CORS(app)

# Inicializar los dispositivos al arrancar el servidor
initialize_devices()

# Iniciar la auditoría de Scapy en el hilo separado
start_continuous_sniffing()

print("Iniciando servidor Flask en http://127.0.0.1:5000...")


@app.route("/api/network_status", methods=["GET"])
def get_network_status():
    """Endpoint principal para que React obtenga el estado de la red."""
    try:
        device_list, status = update_network_status()
        return jsonify({"devices": device_list, "status": status})
    except Exception as e:
        # Esto captura errores si el hilo de sniffing se detiene inesperadamente
        print(f"ERROR: Fallo en la actualización de estado: {e}")
        return jsonify(
            {"devices": [], "status": {"isRunning": False, "simulating": False}}
        ), 500


@app.route("/api/device_action", methods=["POST"])
def device_action():
    """Endpoint para bloquear/desbloquear y cambiar límites desde el frontend."""
    data = request.json
    ip = data.get("ip")
    action = data.get("action")
    limit = data.get("limit")

    with lock:
        if ip in network_devices:
            device = network_devices[ip]

            if action == "block":
                device["status"] = "Blocked"
                print(f"ACCION: Dispositivo {ip} BLOQUEADO manualmente.")
            elif action == "unblock":
                device["status"] = "Connected"
                print(f"ACCION: Dispositivo {ip} DESBLOQUEADO manualmente.")

            if limit is not None:
                try:
                    new_limit = int(limit)
                    if new_limit > 0:
                        device["packetLimit"] = new_limit
                        print(
                            f"ACCION: Límite de paquetes de {ip} actualizado a {new_limit}."
                        )
                except ValueError:
                    pass

            return jsonify({"success": True, "device": device})
        else:
            return jsonify(
                {"success": False, "message": "Dispositivo no encontrado"}
            ), 404


@app.route("/api/reset", methods=["POST"])
def reset_simulation():
    """Endpoint para reiniciar el estado de la red."""
    initialize_devices()
    print("EVENTO: Estado de red reseteado.")
    return jsonify({"success": True, "message": "Estado de red reiniciado"})


if __name__ == "__main__":
    # use_reloader=False es necesario para evitar que el hilo de Scapy se inicie dos veces.
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)