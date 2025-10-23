import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Zap, XCircle, CheckCircle, Lock, Unlock, Wifi, Server, Cpu, Router } from 'lucide-react';

// --- CONFIGURACIÓN DEL FRONTEND ---
const API_BASE_URL = 'http://127.0.0.1:5000/api';
const REFRESH_INTERVAL_MS = 1500; // Frecuencia de petición al backend
const DEFAULT_PACKET_LIMIT = 1500; // Constante utilizada si el dispositivo no tiene límite establecido

// Componente principal de la aplicación
const App = () => {
    const [devices, setDevices] = useState([]);
    const [status, setStatus] = useState({ 
        isRunning: false, 
        isAttackMode: false, 
        attackerIp: null, 
        simulating: true 
    });
    const [log, setLog] = useState([]);
    const [selectedDevice, setSelectedDevice] = useState(null);
    const [modalOpen, setModalOpen] = useState(false);
    const [newLimit, setNewLimit] = useState('');

    const intervalRef = useRef(null);
    const logContainerRef = useRef(null);

    // Función para obtener datos del backend
    const fetchNetworkStatus = useCallback(async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/network_status`);
            if (!response.ok) throw new Error('Network response was not ok');
            const data = await response.json();

            // 1. Detección de Bloqueos (para el log)
            data.devices.forEach(newDevice => {
                const oldDevice = devices.find(d => d.ip === newDevice.ip);
                if (newDevice.status === 'Blocked' && (!oldDevice || oldDevice.status !== 'Blocked')) {
                    const currentRate = newDevice.recentPacketHistory ? newDevice.recentPacketHistory.reduce((a, b) => a + b, 0) : 0;
                    addLogEntry(
                        `[BLOQUEO AUTOMÁTICO] Host ${newDevice.id} (${newDevice.ip}) bloqueado. Tasa de ${currentRate} Pkts/ventana excede límite de ${newDevice.packetLimit}. Protocolo detectado: ${newDevice.last_protocol || 'N/A'}.`, 
                        'critical'
                    );
                }
            });

            // 2. Actualizar estado y dispositivos
            setDevices(data.devices);
            setStatus(prevStatus => ({
                ...prevStatus,
                isRunning: true,
                isAttackMode: data.status.isAttackMode,
                attackerIp: data.status.attackerIp,
                simulating: data.status.simulating
            }));

        } catch (error) {
            console.error("Error al obtener estado de red:", error);
            setStatus(prevStatus => ({ ...prevStatus, isRunning: false }));
            clearInterval(intervalRef.current);
            addLogEntry(`[ERROR] Desconectado del servidor Flask. ${error.message}`, 'critical');
        }
    }, [devices]);

    // Bucle de polling para actualizar el estado
    useEffect(() => {
        if (status.isRunning) {
            if (intervalRef.current) clearInterval(intervalRef.current);
            intervalRef.current = setInterval(fetchNetworkStatus, REFRESH_INTERVAL_MS);
        } else {
            if (intervalRef.current) clearInterval(intervalRef.current);
        }
        
        // Limpieza al desmontar
        return () => {
            if (intervalRef.current) clearInterval(intervalRef.current);
        };
    }, [status.isRunning, fetchNetworkStatus]);

    // Scroll automático del log
    useEffect(() => {
        if (logContainerRef.current) {
            logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
        }
    }, [log]);

    // --- MANEJO DE ESTADO Y LOGS ---

    const addLogEntry = (message, type = 'normal') => {
        setLog(prevLog => {
            const newEntry = { timestamp: new Date().toLocaleTimeString(), message, type };
            // Limitar el log a 100 entradas
            return [...prevLog.slice(-99), newEntry]; 
        });
    };

    const handleStartSimulation = () => {
        setStatus(prevStatus => ({ ...prevStatus, isRunning: true }));
        addLogEntry("[INICIO] Iniciando conexión con el Auditor de Red...", 'normal');
        fetchNetworkStatus();
    };
    
    // Eliminada handleAttackSimulation

    const handleReset = async () => {
        clearInterval(intervalRef.current);
        // Resetting all fields to initial state
        setStatus({ isRunning: false, isAttackMode: false, attackerIp: null, simulating: true });
        setDevices([]);
        setLog([]);
        try {
            await fetch(`${API_BASE_URL}/reset`, { method: 'POST' });
        } catch (error) {
            console.error("Error al resetear backend:", error);
        }
        addLogEntry("[REINICIO] Estado de red reseteado.", 'normal');
    };

    const handleOpenModal = (device) => {
        setSelectedDevice(device);
        setNewLimit(device.packetLimit || DEFAULT_PACKET_LIMIT);
        setModalOpen(true);
    };

    const handleCloseModal = () => {
        setModalOpen(false);
        setSelectedDevice(null);
    };

    // --- ACCIONES DE DISPOSITIVO (Bloqueo/Límite) ---
    const updateDeviceAction = async (action, limit = null) => {
        if (!selectedDevice) return;

        try {
            const payload = { ip: selectedDevice.ip, action, limit: limit !== null ? parseInt(limit, 10) : undefined };
            const response = await fetch(`${API_BASE_URL}/device_action`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (response.ok) {
                const updatedDevice = await response.json();
                
                // Actualizar estado local
                setDevices(prevDevices => 
                    prevDevices.map(d => d.ip === selectedDevice.ip ? { ...d, status: updatedDevice.device.status, packetLimit: updatedDevice.device.packetLimit } : d)
                );
                setSelectedDevice(prev => ({ ...prev, status: updatedDevice.device.status, packetLimit: updatedDevice.device.packetLimit }));
                
                // Registro más detallado
                if (action === 'block') addLogEntry(`[BLOQUEO MANUAL] Host ${selectedDevice.id} (${selectedDevice.ip}) bloqueado por administrador. Último protocolo: ${selectedDevice.last_protocol || 'N/A'}.`, 'critical');
                if (action === 'unblock') addLogEntry(`[DESBLOQUEO MANUAL] Host ${selectedDevice.id} (${selectedDevice.ip}) desbloqueado.`, 'normal');
                if (limit !== null) addLogEntry(`[LÍMITE] Límite de tasa para ${selectedDevice.ip} actualizado a ${newLimit} paquetes.`, 'normal');
                
                if (action !== 'limit') handleCloseModal();
            }
        } catch (error) {
            console.error("Error al realizar acción:", error);
        }
    };

    // --- RENDERIZADO DE UTILIDAD ---
    const getStatusIndicator = () => {
        let colorClass = 'bg-gray-500';
        let text = 'Inactivo';

        if (status.isRunning && status.simulating) {
            colorClass = 'bg-yellow-500 animate-pulse';
            text = 'Auditoría en Fallback (Simulación)';
        } else if (status.isRunning && !status.simulating) {
            colorClass = 'bg-green-500';
            text = 'Auditoría Real Activa';
        }

        const blockedCount = devices.filter(d => d.status === 'Blocked').length;
        if (blockedCount > 0) {
            colorClass = 'bg-red-600 blinking';
            text = `Amenaza Contenida (${blockedCount} Bloqueados)`;
        }
        
        return { colorClass, text };
    };

    const StatusBlock = getStatusIndicator();

    return (
        <div className="min-h-screen p-4 sm:p-6 lg:p-8 bg-gray-900 text-gray-100 font-inter">
            <style>{`
                .card { background-color: #1F2937; border: 1px solid #374151; border-radius: 0.75rem; }
                .log-entry { font-family: 'Courier New', Courier, monospace; font-size: 0.875rem; padding: 0.5rem 0.75rem; border-radius: 0.375rem; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center; }
                .log-normal { background-color: rgba(16, 185, 129, 0.1); border-left: 3px solid #10B981; }
                .log-warning { background-color: rgba(245, 158, 11, 0.1); border-left: 3px solid #F59E0B; }
                .log-critical { background-color: rgba(239, 68, 68, 0.1); border-left: 3px solid #EF4444; }
                .blinking { animation: blinker 1s linear infinite; }
                @keyframes blinker { 50% { opacity: 0.3; } }
            `}</style>
            
            <div className="max-w-7xl mx-auto">
                {/* Encabezado */}
                <header className="mb-8 text-center">
                    <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">Auditor de Red de Detección de Desvío (Flask/React)</h1>
                    <p className="text-lg text-gray-400">Monitoreo y Contraataque Basado en Tasa de Paquetes</p>
                    {status.isRunning && status.simulating && (
                        <p className="text-sm text-yellow-400 mt-2">
                            Advertencia: Actualmente en **Modo Simulación (Fallback)**. El backend Python no pudo inicializar la auditoría real (Scapy).
                        </p>
                    )}
                </header>

                {/* Controles */}
                <div className="card p-4 mb-6 flex flex-wrap justify-center items-center gap-4">
                    <button 
                        onClick={handleStartSimulation} 
                        className={`font-bold py-2 px-4 rounded-lg transition-colors ${status.isRunning ? 'bg-blue-800 text-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700 text-white'}`}
                        disabled={status.isRunning}
                    >
                        {status.isRunning ? 'Auditoría en Curso...' : 'Iniciar Auditoría'}
                    </button>
                    <button 
                        onClick={handleReset} 
                        className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded-lg transition-colors"
                    >
                        Reiniciar
                    </button>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Columna de Dispositivos Conectados (Mejorada) */}
                    <div className="lg:col-span-1">
                        <div className="card p-4 h-full">
                            <h2 className="text-xl font-semibold text-white mb-4 border-b border-gray-600 pb-2">Dispositivos Detectados ({devices.length})</h2>
                            <div id="device-list" className="space-y-3 max-h-96 overflow-y-auto pr-2">
                                {devices.length === 0 ? (
                                    <p className="text-gray-500 text-center py-8">Esperando la detección de tráfico...</p>
                                ) : (
                                    devices.map(device => (
                                        <div 
                                            key={device.ip} 
                                            className={`card p-3 flex justify-between items-center transition-all duration-300 cursor-pointer hover:bg-gray-700 ${device.status === 'Blocked' ? 'border-red-500 border-l-4' : 'border-l-4 border-transparent'}`}
                                            onClick={() => handleOpenModal(device)}
                                        >
                                            <div className="flex flex-col">
                                                <p className="font-semibold text-white flex items-center gap-2">
                                                    {device.status === 'Blocked' ? <XCircle size={16} className="text-red-500" /> : <CheckCircle size={16} className="text-green-500" />}
                                                    {device.id} 
                                                    {device.is_local ? <Router size={16} className="text-blue-400 ml-1" title="Host Local" /> : null}
                                                </p>
                                                <p className="text-xs text-gray-400 font-mono">{device.ip}</p>
                                                <p className="text-xs text-gray-500 mt-1">
                                                    Último Protocolo: 
                                                    <span className="font-mono text-cyan-400 ml-1">{device.last_protocol || 'N/A'}</span>
                                                    {device.last_port && <span className="text-gray-600 ml-2">Puerto: {device.last_port}</span>}
                                                </p>
                                            </div>
                                            <div className="text-right">
                                                <p className="font-mono text-white text-lg">{device.packetCount.toLocaleString()} Pkts</p>
                                                <div className={`flex items-center justify-end gap-1 text-sm ${device.status === 'Blocked' ? 'text-red-500' : 'text-green-400'}`}>
                                                    <span>{device.status}</span>
                                                </div>
                                            </div>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>

                    {/* Columna de Estado y Logs */}
                    <div className="lg:col-span-2 space-y-6">
                        {/* Panel de Estado del Sistema */}
                        <div className="card p-4">
                            <h2 className="text-xl font-semibold text-white mb-3">Estado del Sistema</h2>
                            <div className="flex items-center gap-3 p-3 rounded-lg bg-gray-800">
                                <div className={`w-4 h-4 rounded-full ${StatusBlock.colorClass}`} id="status-indicator"></div>
                                <span className={`font-medium ${StatusBlock.colorClass.includes('red') ? 'text-red-400' : 'text-green-400'}`} id="status-text">{StatusBlock.text}</span>
                            </div>
                            
                            {devices.filter(d => d.status === 'Blocked').length > 0 && (
                                <div className="mt-4 p-3 rounded-lg border-l-4 bg-red-500/10 border-red-500 blinking">
                                    <p className="font-bold text-red-400 flex items-center gap-2"><XCircle size={16} /> ¡AMENAZA CONTENIDA!</p>
                                    <p className="text-sm text-gray-300">Uno o más dispositivos fueron bloqueados automáticamente por exceder la tasa de paquetes permitida. **Revise el log para detalles.**</p>
                                </div>
                            )}
                        </div>

                        {/* Panel de Logs */}
                        <div className="card p-4">
                            <h2 className="text-xl font-semibold text-white mb-4">Registro de Eventos</h2>
                            <div id="traffic-log" ref={logContainerRef} className="h-96 overflow-y-auto bg-gray-900/50 p-3 rounded-lg">
                                {log.length === 0 ? (
                                    <p className="text-gray-500 text-center pt-16">Esperando eventos...</p>
                                ) : (
                                    log.map((entry, index) => (
                                        <div key={index} className={`log-entry log-${entry.type} flex-col items-start`}>
                                            <div className="flex justify-between w-full">
                                                <span className="text-gray-300">{entry.message}</span>
                                            </div>
                                            <span className="text-gray-500 text-xs mt-1 self-end">{entry.timestamp}</span>
                                        </div>
                                    ))
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* Modal de Detalle de Dispositivo */}
            {modalOpen && selectedDevice && (
                <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center p-4 z-50">
                    <div className="card w-full max-w-lg p-6">
                        <h3 className="text-2xl font-bold mb-4 border-b border-gray-600 pb-2 flex items-center gap-3">
                            <Wifi size={24} className="text-cyan-400" /> Detalle de {selectedDevice.id}
                        </h3>

                        {/* Estado y Métricas */}
                        <div className="space-y-3 mb-6">
                            <p className="text-lg">IP: <span className="font-mono text-cyan-400">{selectedDevice.ip}</span></p>
                            <p className="text-lg">Estado: <span className={`font-bold ${selectedDevice.status === 'Blocked' ? 'text-red-500' : 'text-green-500'}`}>{selectedDevice.status}</span></p>
                            
                            <div className="grid grid-cols-2 gap-4 pt-2">
                                <div className="p-3 bg-gray-800 rounded-lg">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><Server size={14} /> Total Paquetes</p>
                                    <p className="text-xl font-bold">{selectedDevice.packetCount.toLocaleString()}</p>
                                </div>
                                <div className="p-3 bg-gray-800 rounded-lg">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><Zap size={14} /> Tasa Actual (5 ciclos)</p>
                                    <p className="text-xl font-bold text-yellow-400">{selectedDevice.recentPacketHistory ? selectedDevice.recentPacketHistory.reduce((a, b) => a + b, 0).toLocaleString() : 0} Pkts</p>
                                </div>
                                <div className="p-3 bg-gray-800 rounded-lg col-span-2">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><Router size={14} /> Último Tráfico</p>
                                    <p className="text-lg font-bold">
                                        {selectedDevice.last_protocol} 
                                        {selectedDevice.last_port && <span> / Puerto: {selectedDevice.last_port}</span>}
                                        <span className="text-gray-500 ml-3 text-sm">{selectedDevice.is_local ? '(Host Local)' : '(Host Remoto)'}</span>
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Control de Límite */}
                        <div className="bg-gray-800 p-4 rounded-lg mb-6">
                            <h4 className="font-semibold mb-2">Límite de Detección (Paquetes por Tasa)</h4>
                            <div className="flex gap-2">
                                <input
                                    type="number"
                                    value={newLimit}
                                    onChange={(e) => setNewLimit(e.target.value)}
                                    placeholder="Límite de Paquetes"
                                    className="flex-grow p-2 rounded-lg bg-gray-700 text-white border border-gray-600 focus:border-cyan-500"
                                    min="1"
                                />
                                <button
                                    onClick={() => updateDeviceAction('limit', newLimit)}
                                    className="bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-2 px-4 rounded-lg transition-colors"
                                >
                                    Guardar
                                </button>
                            </div>
                            <p className="text-sm text-gray-400 mt-2">Umbral: {selectedDevice.packetLimit.toLocaleString()} paquetes en la ventana de 5 ciclos (aprox. 7.5s).</p>
                        </div>

                        {/* Botones de Acción */}
                        <div className="flex justify-between gap-4">
                            <button
                                onClick={handleCloseModal}
                                className="bg-gray-500 hover:bg-gray-600 text-white font-bold py-2 px-4 rounded-lg transition-colors flex-grow"
                            >
                                Cerrar
                            </button>
                            {selectedDevice.status === 'Blocked' ? (
                                <button
                                    onClick={() => updateDeviceAction('unblock')}
                                    className="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 flex-grow"
                                >
                                    <Unlock size={18} /> Desbloquear
                                </button>
                            ) : (
                                <button
                                    onClick={() => updateDeviceAction('block')}
                                    className="bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-lg transition-colors flex items-center justify-center gap-2 flex-grow"
                                >
                                    <Lock size={18} /> Bloquear Manualmente
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default App;
