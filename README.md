# Auditor de Red de Detección de Desvío (Flask/React)


Este proyecto es un auditor de red en tiempo real que utiliza **Python/Flask** y **Scapy** para capturar y analizar el tráfico de red (tasa de paquetes por IP), junto con **React/Vite** para visualizar los datos en un panel interactivo.

## Requisitos Previos

Asegúrate de tener instalado:

- Node.js (versión 20 o superior)
- Python 3 (versión 3.10 o superior)
- Git (opcional)
- Dependencias de captura de paquetes:
  - **Linux/macOS:** `libpcap-dev` y permisos de `sudo`
  - **Windows:** Npcap instalado con modo de compatibilidad

## Instalación y Configuración

1. Instalar dependencias de Node.js (incluye `concurrently`):

   ```bash
   npm install
   ```

   Este comando intentará configurar el entorno de Python automáticamente con el script `postinstall`.

2. Si la instalación automática falla, configura el entorno de Python manualmente:

   ```bash
   npm run setup:python
   ```

   Esto crea el entorno virtual dentro de `python-back/` e instala **Flask** y **Scapy**.

## Ejecución del Proyecto

> **Nota:** El backend utiliza Scapy para capturar tráfico de red, por lo que requiere permisos de administrador/root (`sudo`).

### Terminal 1: Iniciar el Backend

Ejecuta el siguiente comando (puede requerir contraseña de sudo):

```bash
npm run start:flask
```

Si aparece el mensaje `INFO: Hilo de auditoría real iniciado en enp4s0`, el auditor está en funcionamiento.

### Terminal 2: Iniciar el Frontend

Ejecuta el siguiente comando:

```bash
npm run start:react
```

El panel de control se abrirá en `http://localhost:5173` (o un puerto similar) y mostrará los datos en tiempo real enviados por el servidor Flask.
