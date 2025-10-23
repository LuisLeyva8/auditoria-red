# -*- coding: utf-8 -*-
import json
import random
import time
from threading import Thread, Lock
from flask import Flask, jsonify, request
from flask_cors import CORS
from collections import defaultdict

# --- CONFIGURACIÓN DE SCAPY ---
try:
    # Si Scapy falla aquí (e.g., ImportError, falta libpcap), el script se detendrá.
    from scapy.all import sniff, IP, conf, TCP, UDP
    # Interfaz de red confirmada por el usuario
    ACTIVE_INTERFACE = 'enp4s0' 
    print(f"INFO: Scapy cargado exitosamente. Interfaz activa: {ACTIVE_INTERFACE}")
except ImportError as e:
    raise ImportError("ERROR CRÍTICO: No se pudo cargar Scapy. Instala Scapy y/o las dependencias de libpcap.") from e
except Exception as e:
    # Error de inicialización (ej. permisos de socket).
    raise Exception(f"ERROR CRÍTICO: Fallo al inicializar Scapy. Asegúrate de ejecutar con 'sudo'. Error: {e}") from e


# --- CONFIGURACIÓN DE AUDITORÍA ---
# Unidades: Paquetes
DETECTION_WINDOW_SIZE = 5  # Número de ciclos para medir la tasa de paquetes.
DEFAULT_PACKET_LIMIT = 1500 # Límite de paquetes acumulados en la ventana de tiempo para activar la alerta.
SNIFF_TIMEOUT_S = 3         # Duración de cada ciclo de captura de Scapy

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
    
# --- LÓGICA DE CAPTURA DE RED (SCAPY) EN HILO SEPARADO ---

def packet_callback(pkt):
    """Función de callback de Scapy: se llama para cada paquete capturado."""
    global network_devices
    
    # Solo procesamos paquetes IP con capa de origen.
    if IP in pkt and hasattr(pkt[IP], 'src'):
        src_ip = pkt[IP].src
        
        with lock:
            
            # --- Extracción de información detallada ---
            protocol = "ICMP" if pkt.haslayer("ICMP") else (
                       "TCP" if pkt.haslayer(TCP) else (
                       "UDP" if pkt.haslayer(UDP) else "Otros"))
            
            dst_port = ""
            if TCP in pkt:
                dst_port = pkt[TCP].dport
            elif UDP in pkt:
                dst_port = pkt[UDP].dport

            
            # 1. Incorporar nuevos dispositivos encontrados
            if src_ip not in network_devices:
                network_devices[src_ip] = {
                    # La IP 127.0.0.1 se maneja para evitar spam de localhost
                    'id': f"HOST-{src_ip.split('.')[-1]}" if src_ip != '127.0.0.1' else 'LOCALHOST (127.0.0.1)',
                    'ip': src_ip,
                    'status': 'Connected',
                    'packetCount': 0, 
                    'recentPacketHistory': [], 
                    'packetLimit': DEFAULT_PACKET_LIMIT,
                    'last_protocol': protocol,
                    'last_port': dst_port,
                    'is_local': src_ip.startswith('192.168.') or src_ip.startswith('10.') or src_ip.startswith('172.') 
                }
            
            # 2. Solo contar si el dispositivo no está bloqueado
            device = network_devices[src_ip]
            if device['status'] != 'Blocked':
                device['packetCount'] += 1
                device['last_protocol'] = protocol
                device['last_port'] = dst_port
            
def start_continuous_sniffing():
    """Inicia el bucle de captura de Scapy en un hilo dedicado."""
    global is_sniffing_running
    
    if is_sniffing_running:
        return
    
    def sniffing_loop():
        global is_sniffing_running
        is_sniffing_running = True
        print(f"INFO: Hilo de auditoría real iniciado en {ACTIVE_INTERFACE}. Capturando tráfico IP...")
        
        while is_sniffing_running:
            try:
                # Captura de paquetes IP (L3). Llama a packet_callback.
                packets = sniff(prn=packet_callback, filter="ip", iface=ACTIVE_INTERFACE, timeout=SNIFF_TIMEOUT_S)
                
                if len(packets) == 0:
                     print(f"DEBUG: 0 paquetes capturados en el ciclo de {SNIFF_TIMEOUT_S}s.")
                
            except Exception as e:
                print(f"ERROR CRÍTICO en hilo de Scapy. Deteniendo auditoría de red: {e}")
                is_sniffing_running = False # Detener el hilo si falla
                break
            
            # Pequeña pausa
            time.sleep(0.1) 
        print("INFO: Hilo de auditoría real detenido.")

    # Iniciar el hilo y hacerlo un demonio
    thread = Thread(target=sniffing_loop)
    thread.daemon = True 
    thread.start()

# --- LÓGICA DE DETECCIÓN Y REPORTE (LLAMADA POR EL FRONTEND) ---

def update_network_status():
    """Ejecuta la detección de tasa y formatea la respuesta basada en datos reales."""
    global network_devices
    
    if not is_sniffing_running:
        # Si el hilo de sniffing falló o no se inició, no tenemos datos.
        raise Exception("El hilo de auditoría real no está activo. Verifique los logs de error.")
    
    with lock:
        
        # Procesar el tráfico y aplicar la detección
        for ip, device in list(network_devices.items()): 
            if device['status'] == 'Blocked':
                continue
            
            # --- DETECCIÓN POR TASA DE PAQUETES ---
            
            # Calcular paquetes capturados desde la última llamada GET
            if 'lastPacketCount' not in device:
                device['lastPacketCount'] = device['packetCount']
                
            packets_sent_this_cycle = device['packetCount'] - device['lastPacketCount']
            device['lastPacketCount'] = device['packetCount'] # Actualizar la base

            # 2. Registrar solo ciclos con tráfico para la detección
            if packets_sent_this_cycle > 0:
                 device['recentPacketHistory'].append(packets_sent_this_cycle)
            
            # 3. Mantener el historial solo dentro de la ventana de detección
            if len(device['recentPacketHistory']) > DETECTION_WINDOW_SIZE:
                device['recentPacketHistory'].pop(0)

            # 4. Detección por Tasa de Paquetes
            current_rate = sum(device['recentPacketHistory'])
            
            if current_rate > device['packetLimit']:
                # ¡DETECCIÓN DE DESVÍO POR TASA RÁPIDA!
                device['status'] = 'Blocked'
                device['recentPacketHistory'] = [] # Limpiar historial 

                print(f"[CRÍTICO] BLOQUEADO: {ip}. Paquetes en ventana exceden límite: {current_rate} > {device['packetLimit']}")
            
    # Formatear la respuesta para el frontend
    device_list = list(network_devices.values())
    
    # El status ahora es simple
    status = {
        'isRunning': True,
        'simulating': False # Siempre Falso
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

@app.route('/api/network_status', methods=['GET'])
def get_network_status():
    """Endpoint principal para que React obtenga el estado de la red."""
    try:
        device_list, status = update_network_status()
        return jsonify({
            'devices': device_list,
            'status': status
        })
    except Exception as e:
        # Esto captura errores si el hilo de sniffing se detiene inesperadamente
        print(f"ERROR: Fallo en la actualización de estado: {e}")
        return jsonify({"devices": [], "status": {"isRunning": False, "simulating": False}}), 500


@app.route('/api/device_action', methods=['POST'])
def device_action():
    """Endpoint para bloquear/desbloquear y cambiar límites desde el frontend."""
    data = request.json
    ip = data.get('ip')
    action = data.get('action')
    limit = data.get('limit')
    
    with lock:
        if ip in network_devices:
            device = network_devices[ip]
            
            if action == 'block':
                device['status'] = 'Blocked'
                print(f"ACCION: Dispositivo {ip} BLOQUEADO manualmente.")
            elif action == 'unblock':
                device['status'] = 'Connected'
                print(f"ACCION: Dispositivo {ip} DESBLOQUEADO manualmente.")
            
            if limit is not None:
                try:
                    new_limit = int(limit)
                    if new_limit > 0:
                        device['packetLimit'] = new_limit
                        print(f"ACCION: Límite de paquetes de {ip} actualizado a {new_limit}.")
                except ValueError:
                    pass 
            
            return jsonify({"success": True, "device": device})
        else:
            return jsonify({"success": False, "message": "Dispositivo no encontrado"}), 404

@app.route('/api/reset', methods=['POST'])
def reset_simulation():
    """Endpoint para reiniciar el estado de la red."""
    initialize_devices()
    print("EVENTO: Estado de red reseteado.")
    return jsonify({"success": True, "message": "Estado de red reiniciado"})

if __name__ == '__main__':
    # use_reloader=False es necesario para evitar que el hilo de Scapy se inicie dos veces.
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
