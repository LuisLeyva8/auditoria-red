import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
// Importamos los componentes de Chart.js
import { Chart as ChartJS, CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend } from 'chart.js';
import { Line } from 'react-chartjs-2';
import { 
    Zap, XCircle, CheckCircle, Lock, Unlock, Wifi, Server, Cpu, Router, 
    Search, Smartphone, Monitor, Tv, Settings, Globe, Fingerprint, BarChart, Layers 
} from 'lucide-react';

// Registramos los componentes de Chart.js
ChartJS.register(
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend
);

// --- CONFIGURACIÓN DEL FRONTEND ---
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5000/api';
const REFRESH_INTERVAL_MS = 1500; 
const DEFAULT_PACKET_LIMIT = 1500; 
const SNIFF_TIMEOUT_S = 3; // Coincide con el backend para cálculo de tasa (3s)

// --- Mapeo de Tipos de Dispositivo a Iconos ---
const DEVICE_ICONS = {
    'PC/Laptop': Monitor,
    'Móvil/Tablet': Smartphone,
    'Servidor': Server,
    'Doméstico/IoT (TV, etc.)': Tv,
    'N/A': Settings, 
};

// --- Componente de Gráfico de Rendimiento ---
const DeviceChart = ({ device, label, dataKey, color, unit }) => {
    const data = {
        labels: device[dataKey].map((_, i) => `C. ${i + 1}`), // Ciclos de la ventana
        datasets: [
            {
                label: label,
                data: device[dataKey],
                borderColor: color,
                backgroundColor: `${color}40`, // 40 es la opacidad
                tension: 0.3,
                pointRadius: 4,
            },
        ],
    };

    const options = {
        responsive: true,
        plugins: {
            legend: { display: false },
            title: {
                display: true,
                text: `${label} (Últimos ${device[dataKey].length} Ciclos)`,
                color: '#E5E7EB',
            },
        },
        scales: {
            y: {
                beginAtZero: true,
                title: {
                    display: true,
                    text: unit,
                    color: '#9CA3AF',
                },
                ticks: { color: '#9CA3AF' },
                grid: { color: '#374151' },
            },
            x: {
                ticks: { color: '#9CA3AF' },
                grid: { color: '#374151' },
            },
        },
    };

    return <Line data={data} options={options} />;
};

// --- Utilidad para formatear Bytes a KB/s o MB/s ---
const formatBytesPerSecond = (bytesPerCycle, total = false) => {
    // Si es el total, solo formateamos los bytes sin dividir por el tiempo
    let bytesToFormat = total ? bytesPerCycle : bytesPerCycle / SNIFF_TIMEOUT_S;

    if (bytesToFormat < 1024) return `${bytesToFormat.toFixed(0)} B/s`;
    if (bytesToFormat < 1024 * 1024) return `${(bytesToFormat / 1024).toFixed(2)} KB/s`;
    return `${(bytesToFormat / (1024 * 1024)).toFixed(2)} MB/s`;
};


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

    const [searchTerm, setSearchTerm] = useState('');
    const [filterType, setFilterType] = useState('all'); 

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
    
    // -----------------------------------------------------------
    // * NUEVO EFECTO: SINCRONIZAR EL MODAL CON LA ÚLTIMA VERSIÓN DE LOS DATOS *
    // -----------------------------------------------------------
    useEffect(() => {
        // Solo ejecuta si el modal está abierto y hay un dispositivo seleccionado.
        if (modalOpen && selectedDevice) {
            // Busca la versión más reciente del dispositivo en la lista 'devices'
            const updatedDevice = devices.find(d => d.ip === selectedDevice.ip);
            
            // Si lo encuentra y es diferente, actualiza el estado local del modal.
            if (updatedDevice && JSON.stringify(updatedDevice) !== JSON.stringify(selectedDevice)) {
                setSelectedDevice(updatedDevice);
            }
        }
    }, [devices, modalOpen, selectedDevice]);


    // Bucle de polling para actualizar el estado (sin cambios)
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
            return [...prevLog.slice(-99), newEntry]; 
        });
    };

    const handleStartSimulation = () => {
        setStatus(prevStatus => ({ ...prevStatus, isRunning: true }));
        addLogEntry("[INICIO] Iniciando conexión con el Auditor de Red...", 'normal');
        fetchNetworkStatus();
    };
    
    const handleReset = async () => {
        clearInterval(intervalRef.current);
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
                
                setDevices(prevDevices => 
                    prevDevices.map(d => d.ip === selectedDevice.ip ? { 
                        ...d, 
                        status: updatedDevice.device.status, 
                        packetLimit: updatedDevice.device.packetLimit 
                    } : d)
                );
                // NOTA: Se comenta la línea de setSelectedDevice para que el useEffect se encargue de la actualización:
                // setSelectedDevice(prev => ({ 
                //     ...prev, 
                //     status: updatedDevice.device.status, 
                //     packetLimit: updatedDevice.device.packetLimit 
                // }));
                
                if (action === 'block') addLogEntry(`[BLOQUEO MANUAL] Host ${selectedDevice.id} (${selectedDevice.ip}) bloqueado por administrador. Último protocolo: ${selectedDevice.last_protocol || 'N/A'}.`, 'critical');
                if (action === 'unblock') addLogEntry(`[DESBLOQUEO MANUAL] Host ${selectedDevice.id} (${selectedDevice.ip}) desbloqueado.`, 'normal');
                if (limit !== null) addLogEntry(`[LÍMITE] Límite de tasa para ${selectedDevice.ip} actualizado a ${newLimit} paquetes.`, 'normal');
                
                if (action !== 'limit') handleCloseModal();
            }
        } catch (error) {
            console.error("Error al realizar acción:", error);
        }
    };
    
    // --- Lógica de Filtrado y Búsqueda ---
    const filteredDevices = useMemo(() => {
        return devices
            .filter(device => {
                if (filterType !== 'all' && device.deviceType !== filterType) {
                    return false;
                }

                if (searchTerm.trim() === '') {
                    return true;
                }
                
                const lowerSearchTerm = searchTerm.toLowerCase();
                const matchesIp = device.ip.toLowerCase().includes(lowerSearchTerm);
                const matchesId = device.id.toLowerCase().includes(lowerSearchTerm);
                const matchesMac = device.macAddress?.toLowerCase().includes(lowerSearchTerm);
                const matchesManufacturer = device.manufacturer?.toLowerCase().includes(lowerSearchTerm);

                return matchesIp || matchesId || matchesMac || matchesManufacturer;
            })
            .sort((a, b) => (a.status === 'Blocked' ? -1 : 1));
    }, [devices, filterType, searchTerm]);

    // Obtener la lista única de tipos de dispositivos para el filtro
    const availableDeviceTypes = useMemo(() => {
        const types = devices.map(d => d.deviceType).filter(Boolean);
        return [...new Set(types)].sort();
    }, [devices]);
    
    // Función para obtener el componente Icono del Dispositivo
    const getDeviceIcon = (deviceType) => {
        const IconComponent = DEVICE_ICONS[deviceType] || DEVICE_ICONS['N/A'];
        return <IconComponent size={16} className="text-purple-400" title={deviceType} />;
    };
    // --- FIN Lógica de Filtrado y Búsqueda ---


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

                {/* Controles Principales */}
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
                
                {/* SECCIÓN: BÚSQUEDA Y FILTRO */}
                <div className="card p-4 mb-6 grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="md:col-span-2 relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" size={18} />
                        <input
                            type="text"
                            placeholder="Buscar por IP, ID, MAC o Fabricante..." 
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            className="w-full p-2 pl-10 rounded-lg bg-gray-800 text-white border border-gray-700 focus:border-cyan-500"
                        />
                    </div>
                    <div>
                        <select
                            value={filterType}
                            onChange={(e) => setFilterType(e.target.value)}
                            className="w-full p-2 rounded-lg bg-gray-800 text-white border border-gray-700 focus:border-cyan-500 appearance-none pr-8"
                        >
                            <option value="all">Filtrar por Tipo (Todos)</option>
                            {availableDeviceTypes.map(type => (
                                <option key={type} value={type}>{type}</option>
                            ))}
                        </select>
                    </div>
                </div>
                {/* FIN SECCIÓN BÚSQUEDA Y FILTRO */}


                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Columna de Dispositivos Conectados (Mejorada) */}
                    <div className="lg:col-span-1">
                        <div className="card p-4 h-full">
                            <h2 className="text-xl font-semibold text-white mb-4 border-b border-gray-600 pb-2">Dispositivos Detectados ({filteredDevices.length} de {devices.length})</h2>
                            <div id="device-list" className="space-y-3 max-h-96 overflow-y-auto pr-2">
                                {devices.length === 0 ? (
                                    <p className="text-gray-500 text-center py-8">Esperando la detección de tráfico...</p>
                                ) : filteredDevices.length === 0 ? (
                                    <p className="text-gray-500 text-center py-8">No se encontraron dispositivos con los filtros aplicados.</p>
                                ) : (
                                    filteredDevices.map(device => (
                                        <div 
                                            key={device.ip} 
                                            className={`card p-3 flex justify-between items-center transition-all duration-300 cursor-pointer hover:bg-gray-700 ${device.status === 'Blocked' ? 'border-red-500 border-l-4' : 'border-l-4 border-transparent'}`}
                                            onClick={() => handleOpenModal(device)}
                                        >
                                            <div className="flex flex-col">
                                                {/* Icono de Dispositivo y Título */}
                                                <p className="font-semibold text-white flex items-center gap-2">
                                                    {device.status === 'Blocked' ? <XCircle size={16} className="text-red-500" /> : <CheckCircle size={16} className="text-green-500" />}
                                                    {getDeviceIcon(device.deviceType)}
                                                    {device.id} 
                                                    {device.is_local ? <Router size={16} className="text-blue-400 ml-1" title="Host Local" /> : null}
                                                </p>
                                                <p className="text-xs text-gray-400 font-mono">{device.ip}</p>
                                                <p className="text-xs text-gray-400 mt-1">
                                                    Tipo: <span className="text-purple-300 ml-1 font-semibold">{device.deviceType || 'N/A'}</span>
                                                </p>
                                                {device.macAddress && (
                                                     <p className="text-xs text-cyan-400 mt-1 flex items-center gap-1">
                                                        <Fingerprint size={12} />
                                                        Fabricante: <span className="font-semibold text-cyan-300">{device.manufacturer || 'N/A'}</span>
                                                    </p>
                                                )}
                                                <p className="text-xs text-gray-500 mt-1 font-mono">
                                                    MAC: {device.macAddress || 'N/A'}
                                                </p>
                                                <p className="text-xs text-gray-500 mt-1">
                                                    Último Protocolo: 
                                                    <span className="font-mono text-cyan-400 ml-1">{device.last_protocol || 'N/A'}</span>
                                                    {device.last_port && <span className="text-gray-600 ml-2">Puerto: {device.last_port}</span>}
                                                </p>
                                                {device.last_visited_domain && device.last_visited_domain !== "N/A o Protocolo No Web" && (
                                                    <p className="text-xs text-yellow-400 mt-1 flex items-center gap-1">
                                                        <Globe size={12} />
                                                        Dominio: <span className="font-mono text-yellow-300">{device.last_visited_domain}</span>
                                                    </p>
                                                )}
                                            </div>
                                            <div className="text-right">
                                                <p className="font-mono text-white text-lg">{device.packetCount.toLocaleString()} Pkts</p>
                                                <p className="font-mono text-sm text-green-400">{formatBytesPerSecond(device.recentBandwidthRate.reduce((a, b) => a + b, 0))}</p>
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

                    {/* Columna de Estado y Logs (sin cambios) */}
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

            {/* Modal de Detalle de Dispositivo (Actualizado) */}
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
                            
                            <div className="grid grid-cols-2 gap-4">
                                <p className="text-lg flex items-center gap-2">
                                    {getDeviceIcon(selectedDevice.deviceType)}
                                    Tipo: <span className="font-bold text-purple-300">{selectedDevice.deviceType || 'N/A'}</span>
                                </p>
                                {/* --- NUEVO: Fingerprinting de SO --- */}
                                <p className="text-lg flex items-center gap-2">
                                    <Cpu size={20} className="text-orange-400" />
                                    SO Estimado: <span className="font-bold text-orange-300">{selectedDevice.os_fingerprint || 'N/A'}</span>
                                </p>
                                {/* ----------------------------------- */}
                            </div>
                            
                            <p className="text-lg flex items-center gap-2 pt-2">
                                <Fingerprint size={20} className="text-cyan-400" />
                                Fabricante: <span className="font-bold text-cyan-300">{selectedDevice.manufacturer || 'N/A'}</span>
                            </p>

                            <p className="text-lg flex items-center gap-2 pt-2">
                                <Globe size={20} className="text-yellow-400" />
                                Último Dominio: 
                                <span className="font-mono text-yellow-300 break-all">{selectedDevice.last_visited_domain || 'N/A'}</span>
                            </p>
                            
                            <div className="grid grid-cols-2 gap-4 pt-4">
                                <div className="p-3 bg-gray-800 rounded-lg">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><Server size={14} /> Paquetes Totales</p>
                                    <p className="text-xl font-bold">{selectedDevice.packetCount.toLocaleString()}</p>
                                </div>
                                <div className="p-3 bg-gray-800 rounded-lg">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><Layers size={14} /> Bytes Totales</p>
                                    <p className="text-xl font-bold">{formatBytesPerSecond(selectedDevice.bandwidthHistoryTotal, true)}</p>
                                </div>
                                <div className="p-3 bg-gray-800 rounded-lg">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><Zap size={14} /> Tasa Paquetes (5 ciclos)</p>
                                    <p className="text-xl font-bold text-yellow-400">{selectedDevice.recentPacketHistory ? selectedDevice.recentPacketHistory.reduce((a, b) => a + b, 0).toLocaleString() : 0} Pkts</p>
                                </div>
                                {/* --- NUEVO: Tasa de Ancho de Banda --- */}
                                <div className="p-3 bg-gray-800 rounded-lg">
                                    <p className="text-sm text-gray-400 flex items-center gap-1"><BarChart size={14} /> Tasa Ancho Banda (5 ciclos)</p>
                                    <p className="text-xl font-bold text-green-400">
                                        {formatBytesPerSecond(selectedDevice.recentBandwidthRate.reduce((a, b) => a + b, 0))}
                                    </p>
                                </div>
                                {/* -------------------------------------- */}
                            </div>
                        </div>

                        {/* --- Gráficos de Tendencia en Vivo --- */}
                        <div className="space-y-6">
                            <div className="card p-4">
                                <DeviceChart 
                                    device={selectedDevice} 
                                    label="Tasa de Paquetes" 
                                    dataKey="recentPacketHistory" 
                                    color="#F59E0B" 
                                    unit="Paquetes"
                                />
                            </div>
                            <div className="card p-4">
                                <DeviceChart 
                                    device={selectedDevice} 
                                    label="Tasa de Ancho de Banda (Bytes)" 
                                    dataKey="recentBandwidthRate" 
                                    color="#10B981" 
                                    unit="Bytes"
                                />
                                <p className="text-xs text-gray-500 mt-2 text-center">Nota: La escala de Y muestra Bytes acumulados en el ciclo de {SNIFF_TIMEOUT_S}s.</p>
                            </div>
                        </div>
                        {/* --- FIN Gráficos de Tendencia --- */}

                        {/* Control de Límite */}
                        <div className="bg-gray-800 p-4 rounded-lg mt-6">
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
                        <div className="flex justify-between gap-4 pt-4">
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