import React, { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Zap, Shield, XCircle, CheckCircle, Clock } from 'lucide-react';

// --- CONFIGURACIÓN DE LA APLICACIÓN Y BACKEND ---
// NOTA: Asume que el servidor Flask se ejecuta en http://127.0.0.1:5000
const API_URL = 'http://127.0.0.1:5000/api';
const POLLING_INTERVAL_MS = 1500; // Intervalo de actualización de datos
const PACKET_RATE_CHECK_INTERVAL_COUNT = 5; // Debe coincidir con el servidor Python
const SIMULATION_INTERVAL_MS = 1500; // Debe coincidir con el servidor Python (para el cálculo de la ventana)

// Componente principal
const App = () => {
  const [devices, setDevices] = useState([]);
  const [systemStatus, setSystemStatus] = useState('Inactivo');
  const [isLoading, setIsLoading] = useState(false);
  const [alertMessage, setAlertMessage] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [logs, setLogs] = useState([]);

  // --- LÓGICA DE UTILIDAD ---

  const formatTime = (ms) => {
    const totalSeconds = Math.floor(ms / 1000);
    const days = Math.floor(totalSeconds / (3600 * 24));
    const hours = Math.floor((totalSeconds % (3600 * 24)) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;
    let parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (seconds > 0 || parts.length === 0) parts.push(`${seconds}s`);
    return parts.join(' ');
  };

  const addLog = (ip, message, type) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs(prevLogs => [{ timestamp, ip, message, type }, ...prevLogs]);
  };

  const showAlert = (message, type) => {
    setAlertMessage({ message, type });
  };

  // --- LÓGICA DE COMUNICACIÓN CON FLASK ---

  const fetchNetworkStatus = useCallback(async () => {
    if (systemStatus === 'Inactivo') return;

    try {
      setIsLoading(true);
      const response = await fetch(`${API_URL}/network_status`);
      if (!response.ok) throw new Error('Error al obtener el estado de la red.');

      const newDevices = await response.json();
      
      // Procesar y actualizar logs y alertas
      newDevices.forEach(newDev => {
        const oldDev = devices.find(d => d.ip === newDev.ip);
        
        if (oldDev && newDev.status !== oldDev.status) {
          const logType = newDev.status === 'ALERT' ? 'warning' : newDev.status === 'Blocked' ? 'critical' : 'normal';
          const alertMsg = newDev.status === 'ALERT' 
            ? `ALERTA: Tasa de paquetes anómala detectada en ${newDev.ip}.`
            : newDev.status === 'Blocked' 
            ? `¡BLOQUEADO! Dispositivo ${newDev.ip} ha sido aislado.` // Esto solo si la función de bloqueo estuviera activa
            : `Dispositivo ${newDev.ip} ha vuelto a la normalidad.`;
          
          if (logType !== 'normal') {
            addLog(newDev.ip, alertMsg, logType);
            showAlert(alertMsg, logType);
          }
        } 
        
        // Loguear tráfico si el conteo de paquetes no es trivial
        if (oldDev && newDev.packetsSent > oldDev.packetsSent) {
          const packetsThisTurn = newDev.packetsSent - oldDev.packetsSent;
          if (packetsThisTurn > 100) { // Si más de 100 paquetes por ciclo, loguear
            addLog(newDev.ip, `Paquetes enviados: ${packetsThisTurn.toFixed(0)}`, newDev.status === 'ALERT' ? 'warning' : 'normal');
          }
        }
      });

      setDevices(newDevices);
      setIsLoading(false);

      // Actualizar estado general del sistema basado en los dispositivos
      const hasAlert = newDevices.some(d => d.status === 'ALERT');
      const isBlocked = newDevices.some(d => d.status === 'Blocked');
      
      if (isBlocked) {
        setSystemStatus('Amenaza Contenida');
      } else if (hasAlert) {
        setSystemStatus('ALERTA - Tráfico Anómalo');
      } else {
        setSystemStatus('Sistema Operacional - Monitoreando');
      }

    } catch (error) {
      console.error('Error al obtener datos de red:', error);
      setIsLoading(false);
      setSystemStatus('Error de Conexión');
    }
  }, [systemStatus, devices]);


  // --- MANEJADORES DE ACCIONES ---

  const handleStart = () => {
    setSystemStatus('Sistema Operacional - Monitoreando');
    setLogs([{ timestamp: new Date().toLocaleTimeString(), ip: 'SYSTEM', message: 'Monitoreo iniciado. Conectando al servidor Flask...', type: 'normal' }]);
    setAlertMessage('');
  };

  const handleReset = async () => {
    try {
      await fetch(`${API_URL}/reset`, { method: 'POST' });
      setSystemStatus('Inactivo');
      setDevices([]);
      setLogs([]);
      setAlertMessage('');
    } catch (error) {
      console.error('Error al resetear:', error);
      showAlert('Error al intentar resetear el servidor.', 'critical');
    }
  };

  const openModal = (device) => {
    setSelectedDevice(device);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setSelectedDevice(null);
  };

  const handleToggleBlock = async () => {
    if (!selectedDevice) return;
    const action = selectedDevice.status === 'Blocked' ? 'unblock' : 'block';
    
    try {
      // Simular la acción en el servidor (el servidor Flask tiene los endpoints /block y /unblock)
      const response = await fetch(`${API_URL}/device/${selectedDevice.ip}/${action}`, { method: 'POST' });
      if (!response.ok) throw new Error(`Fallo al ${action} el dispositivo.`);

      const message = await response.json();
      
      addLog(selectedDevice.ip, `Acción manual: ${message.message}`, action === 'block' ? 'critical' : 'normal');
      showAlert(message.message, action === 'block' ? 'critical' : 'normal');

      // Actualizar el estado local (la próxima llamada a fetchNetworkStatus lo confirmará)
      const updatedDevices = devices.map(d => 
        d.ip === selectedDevice.ip ? { ...d, status: action === 'block' ? 'Blocked' : 'Connected' } : d
      );
      setDevices(updatedDevices);
      setSelectedDevice(prev => ({ ...prev, status: action === 'block' ? 'Blocked' : 'Connected' }));
      
    } catch (error) {
      showAlert(`Error en el control manual: ${error.message}`, 'critical');
    }
  };

  const handleApplyLimit = () => {
    if (!selectedDevice) return;
    const newLimit = parseInt(document.getElementById('data-limit-input').value);

    if (isNaN(newLimit) || newLimit < 500) {
      showAlert("El límite debe ser un número entero válido mayor o igual a 500 Paquetes.", 'warning');
      return;
    }

    // Como es solo un simulador de límite, lo actualizamos solo en el frontend por ahora
    const updatedDevices = devices.map(d => 
      d.ip === selectedDevice.ip ? { ...d, packetRateLimit: newLimit } : d
    );
    setDevices(updatedDevices);
    setSelectedDevice(prev => ({ ...prev, packetRateLimit: newLimit }));

    showAlert(`Límite de TASA para ${selectedDevice.ip} establecido en ${newLimit} Paquetes.`, 'normal');
  };

  // --- HOOKS DE EFECTO ---

  // Polling para obtener el estado de la red
  useEffect(() => {
    let interval;
    if (systemStatus !== 'Inactivo' && systemStatus !== 'Error de Conexión') {
      interval = setInterval(fetchNetworkStatus, POLLING_INTERVAL_MS);
    }
    return () => clearInterval(interval);
  }, [fetchNetworkStatus, systemStatus]);

  // --- RENDERIZADO DEL ESTADO DEL SISTEMA ---

  const renderSystemStatus = () => {
    let indicatorClass = 'bg-gray-500';
    let textClass = 'text-gray-400';
    let isBlinking = false;

    if (systemStatus.includes('Operacional')) {
      indicatorClass = 'bg-green-500';
      textClass = 'text-green-400';
    } else if (systemStatus.includes('ALERTA')) {
      indicatorClass = 'bg-yellow-500';
      textClass = 'text-yellow-400';
      isBlinking = true;
    } else if (systemStatus.includes('Contenida') || systemStatus.includes('Error')) {
      indicatorClass = 'bg-red-500';
      textClass = 'text-red-400';
    }

    return (
      <div className="card p-4 cursor-default">
        <h2 className="text-xl font-semibold text-white mb-3">Estado del Sistema</h2>
        <div id="system-status" className="flex items-center gap-3 p-3 rounded-lg bg-gray-800">
          <div className={`w-4 h-4 rounded-full ${indicatorClass} ${isBlinking ? 'blinking' : ''}`} id="status-indicator"></div>
          <span id="status-text" className={`font-medium ${textClass}`}>{systemStatus}</span>
        </div>
        {alertMessage && (
          <div className={`p-3 rounded-lg border-l-4 mt-4 ${alertMessage.type === 'critical' ? 'bg-red-500/10 border-red-500' : 'bg-yellow-500/10 border-yellow-500'}`}>
            <p className="font-bold">{alertMessage.type === 'critical' ? '¡AMENAZA DETECTADA!' : 'ALERTA DE SEGURIDAD'}</p>
            <p className="text-sm text-gray-300">{alertMessage.message}</p>
          </div>
        )}
      </div>
    );
  };

  // --- RENDERIZADO DEL MODAL ---
  
  const DeviceModal = () => {
    if (!selectedDevice) return null;

    const connectionDurationMs = Date.now() - selectedDevice.connectionStartTime || 0;
    const formattedTime = formatTime(connectionDurationMs);

    const isBlocked = selectedDevice.status === 'Blocked';
    const blockBtnClass = isBlocked ? 'bg-green-600 hover:bg-green-700' : 'bg-red-600 hover:bg-red-700';

    return (
      <div className={`fixed inset-0 bg-black bg-opacity-75 z-50 ${isModalOpen ? 'flex' : 'hidden'} items-center justify-center p-4`}>
        <div className="card w-full max-w-lg p-6 space-y-4 cursor-default">
          <h2 className="text-2xl font-bold text-white border-b border-gray-600 pb-2">Detalles de {selectedDevice.id}</h2>
          
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><p className="text-gray-400">ID:</p><p className="text-white font-medium">{selectedDevice.id}</p></div>
            <div><p className="text-gray-400">IP:</p><p className="text-white font-medium">{selectedDevice.ip}</p></div>
            <div><p className="text-gray-400">Tiempo Conectado:</p><p className="text-white font-medium">{formattedTime}</p></div>
            <div><p className="text-gray-400">Paquetes Enviados (Total):</p><p className="text-white font-medium">{selectedDevice.packetsSent.toFixed(0)} Paquetes</p></div>
            <div className="col-span-2"><p className="text-gray-400">Media de Paquetes Diaria Simulada:</p><p className="text-white font-medium">{selectedDevice.dailyAverage} Paquetes</p></div>
          </div>

          <div className="pt-4 border-t border-gray-700">
            <h3 className="text-lg font-semibold text-white mb-2">Gestión de Límite de Tasa de Paquetes</h3>
            <p className="text-sm text-gray-400 mb-2">Umbral de paquetes en los últimos ${PACKET_RATE_CHECK_INTERVAL_COUNT * SIMULATION_INTERVAL_MS / 1000} segundos para activar el bloqueo.</p>
            <div className="flex items-center space-x-2">
              <input type="number" id="data-limit-input" min="500" defaultValue={selectedDevice.packetRateLimit} className="flex-grow p-2 rounded-lg bg-gray-700 border border-gray-600 text-white focus:ring-yellow-500 focus:border-yellow-500" placeholder="Nuevo Límite (Paquetes)"/>
              <button onClick={handleApplyLimit} className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg transition-colors">Aplicar Límite</button>
            </div>
            <p className="text-sm text-gray-400 mt-2">Límite actual: {selectedDevice.packetRateLimit} Paquetes</p>
          </div>

          <div className="pt-4 border-t border-gray-700 flex justify-between items-center">
            <button 
              onClick={handleToggleBlock} 
              className={`font-bold py-2 px-4 rounded-lg transition-colors ${blockBtnClass}`}
            >
              {isBlocked ? 'Desbloquear Dispositivo' : 'Bloquear Dispositivo'}
            </button>
            <button onClick={closeModal} className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded-lg transition-colors">Cerrar</button>
          </div>
        </div>
      </div>
    );
  };


  // --- LAYOUT PRINCIPAL ---
  return (
    <div className="p-4 sm:p-6 lg:p-8">
      <div className="max-w-7xl mx-auto">
        <header className="mb-8 text-center">
          <h1 className="text-3xl sm:text-4xl font-bold text-white mb-2">Auditor de Extracción de Red (React/Flask)</h1>
          <p className="text-lg text-gray-400">Monitoreo funcional en tiempo real para detección de exfiltración de paquetes</p>
        </header>

        {/* Controles */}
        <div className="card p-4 mb-6 flex flex-wrap justify-center items-center gap-4 cursor-default">
            <button 
              onClick={handleStart} 
              disabled={systemStatus !== 'Inactivo' && systemStatus !== 'Error de Conexión'}
              className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-lg transition-colors disabled:opacity-50"
            >
              <RefreshCw className="inline w-4 h-4 mr-2" />
              Iniciar Auditoría
            </button>
            <button 
              onClick={handleReset} 
              className="bg-gray-600 hover:bg-gray-700 text-white font-bold py-2 px-4 rounded-lg transition-colors"
            >
              Reiniciar Servidor
            </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Dispositivos Conectados */}
          <div className="lg:col-span-1">
            <div className="card p-4 h-full cursor-default">
              <h2 className="text-xl font-semibold text-white mb-4 border-b border-gray-600 pb-2">Dispositivos Conectados ({devices.length})</h2>
              <div id="device-list" className="space-y-3">
                {isLoading && devices.length === 0 ? (
                    <p className="text-yellow-400 text-center py-8 flex items-center justify-center">
                        <RefreshCw className="animate-spin w-5 h-5 mr-2" /> Cargando datos...
                    </p>
                ) : devices.length === 0 ? (
                    <p className="text-gray-500 text-center py-8">Auditoría no iniciada o error de conexión.</p>
                ) : (
                    devices.map(device => {
                      const statusColorClass = device.status === 'ALERT' ? 'text-yellow-400' : device.status === 'Blocked' ? 'text-red-500' : 'text-green-400';
                      const statusIcon = device.status === 'Blocked' ? <XCircle className="h-5 w-5" /> : <CheckCircle className="h-5 w-5" />;
                      
                      return (
                        <div 
                          key={device.ip}
                          className={`card p-3 flex justify-between items-center transition-all duration-300 ${device.status === 'Blocked' ? 'border-red-500' : (device.status === 'ALERT' ? 'border-yellow-500' : 'hover:bg-gray-700')}`}
                          onClick={() => openModal(device)}
                        >
                          <div>
                            <p className="font-semibold text-white">{device.id} {device.isAttacker && <Zap className="inline w-4 h-4 text-red-400 ml-1" />}</p>
                            <p className="text-sm text-gray-400">{device.ip}</p>
                          </div>
                          <div className="text-right">
                            <p className="font-mono text-white text-lg">{device.packetsSent.toFixed(0)} Pkts</p>
                            <div className={`flex items-center justify-end gap-1 text-sm ${statusColorClass}`}>
                              {statusIcon}
                              <span>{device.status === 'ALERT' ? 'Alerta' : (device.status === 'Blocked' ? 'Bloqueado' : 'Conectado')}</span>
                            </div>
                          </div>
                        </div>
                      );
                    })
                )}
              </div>
            </div>
          </div>

          {/* Tráfico y Alertas */}
          <div className="lg:col-span-2 space-y-6">
            {renderSystemStatus()}

            <div className="card p-4 cursor-default">
              <h2 className="text-xl font-semibold text-white mb-4">Registro de Tráfico de Paquetes</h2>
              <div id="traffic-log" className="h-96 overflow-y-auto bg-gray-900/50 p-3 rounded-lg flex flex-col-reverse">
                {logs.length === 0 ? (
                    <p className="text-gray-500 text-center pt-16">Esperando inicio de la auditoría...</p>
                ) : (
                    logs.map((log, index) => {
                        const logClass = log.type === 'normal' ? 'log-normal' : log.type === 'warning' ? 'log-warning' : 'log-critical';
                        return (
                            <div key={index} className={`log-entry ${logClass}`}>
                                <span>
                                    <span className="text-gray-500 mr-2">{log.timestamp}</span>
                                    <span className="text-cyan-400">{log.ip}</span>
                                </span>
                                <span className="text-gray-300">{log.message}</span>
                            </div>
                        );
                    })
                )}
              </div>
            </div>
          </div>
        </div>
        <DeviceModal />
      </div>
    </div>
  );
};

export default App;
