# Laboratorios Semana 3 - Rastreo y Reconocimiento (CY-203 Hackeo Ético)

## Introducción general

En este módulo exploraremos los conceptos de reconocimiento y rastreo de redes mediante escaneo de puertos, análisis de respuestas de servicios y deducción del sistema operativo remoto. Estas técnicas forman parte de las primeras fases del hacking ético, y su correcta aplicación permite entender cómo funciona la infraestructura de red y detectar vulnerabilidades.

### ¿Qué son los puertos?
Los puertos son puntos lógicos de comunicación que permiten a los servicios o aplicaciones recibir y enviar información. Se clasifican en:
- **Puertos bien conocidos (0–1023):** asignados a servicios estándar (ej. 80 para HTTP, 22 para SSH).
- **Puertos registrados (1024–49151):** asignados por IANA para aplicaciones específicas.
- **Puertos dinámicos o privados (49152–65535):** usados temporalmente por el sistema operativo o aplicaciones.

Los escáneres como `nmap` permiten detectar qué puertos están abiertos y qué servicios responden a ellos.

### Herramientas utilizadas

- **`nmap`**: Herramienta de escaneo de puertos, detección de servicios y sistema operativo remoto.
- **`wireshark`**: Analizador de tráfico de red. Permite visualizar en detalle los paquetes que se transmiten y reciben.
- **`netcat (nc)`**: Herramienta para conexiones de red. Permite probar puertos manualmente y ver respuestas de servidores (banner grabbing).
- **`telnet`**: Cliente simple que permite conectarse a un puerto TCP para probar si responde.
- **`ping`**: Comando básico para verificar conectividad mediante mensajes ICMP.
- **`whois`, `dig`, `nslookup`**: Herramientas de reconocimiento pasivo para analizar dominios públicos.

### Significado de siglas y campos clave

- **`SYN` (Synchronize):** Paquete inicial en una conexión TCP.
- **`SYN-ACK`:** Paquete de respuesta del servidor indicando que acepta iniciar la conexión.
- **`ACK` (Acknowledgement):** Paquete final del three-way handshake.
- **`TTL` (Time to Live):** Valor que indica la cantidad máxima de saltos que un paquete puede recorrer. También da pistas del sistema operativo (ej. TTL ≈ 64 en Linux, ≈ 128 en Windows).
- **`TCP` (Transmission Control Protocol):** Protocolo confiable y orientado a conexión.
- **`ICMP` (Internet Control Message Protocol):** Protocolo de red usado para mensajes de control como `ping`.

Estas definiciones te ayudarán a comprender mejor lo que estás viendo en Wireshark o nmap, y tomar decisiones informadas durante el análisis.


Este documento contiene 3 laboratorios progresivos para enseñar escaneo de red, evasiones y análisis de sistema operativo utilizando herramientas de red reales.

---

## Laboratorio 1: Reconocimiento Activo con Nmap y Wireshark

### Objetivo
Comprender el escaneo SYN, el modelo TCP y analizar un three-way handshake con Wireshark.

### Setup y herramientas

**IMPORTANTE**: Asegúrate de configurar la red de la VM de Kali Linux en modo **Bridge Adapter** desde VirtualBox, VMware o UTM. Esto le permitirá tener una IP en la misma red que el host (por ejemplo, 192.168.x.x) y poder comunicarse con los contenedores Docker que exponen puertos. Esta opción debe activarse con la VM apagada, en la sección de red del software de virtualización.
- **VM de Kali Linux** como atacante (VirtualBox, VMware, UTM o Parallels).
- **Máquina víctima**: Contenedor vulnerable usando Docker en el host o una segunda VM.
  ```bash
  docker pull vulnerables/web-dvwa
  docker run -d -p 80:80 -p 22:22 --name vulnerable vulnerables/web-dvwa
  ```
- Herramientas dentro de la VM Kali:
  - `nmap`
  - `wireshark`
  - `netcat`, `telnet`, `ping`

### Instrucciones paso a paso

**Sugerencia útil**: Para facilitar la ejecución de comandos, puedes definir una variable de entorno en Kali con la IP del objetivo:
```bash
export OBJETIVO=192.168.50.187  # Reemplaza con la IP de tu host
```
Luego usa `$OBJETIVO` en lugar de escribir la IP completa:

0. Si estás usando puertos expuestos (`-p 80:80 -p 22:22`), **no uses la IP interna del contenedor**.
   En su lugar, desde Kali, escanea la IP del **host** (ej. `192.168.1.x`).
   Puedes verificar la IP del host con:
   ```bash
   # En el host:
   # En macOS usa:
   ifconfig | grep 'inet '
   # En Linux:
   ip a
   # En Windows (CMD o PowerShell):
   ipconfig

   # (opcional) Para ver la IP interna del contenedor (no siempre útil con puertos expuestos):
docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' vulnerable
   ```
1. Desde Kali, verifica conectividad con la víctima:
   ```bash
   ping $OBJETIVO
   ```
2. Ejecutar escaneo SYN:
   ```bash
   nmap -sS -T4 -Pn $OBJETIVO
   ```
3. Ejecutar escaneo de versión y sistema operativo:
   ```bash
   nmap -sV -O $OBJETIVO
   ```
4. Capturar paquetes con Wireshark:
   - Abre Wireshark desde Kali:
     ```bash
     wireshark &
     ```
   - Selecciona la interfaz de red correcta (como `eth0` o `enp0s3`).
   - Inicia la captura **antes de ejecutar el escaneo nmap**.
   - En otra terminal, ejecuta:
     ```bash
     nmap -sS -T4 -Pn $OBJETIVO
     ```
   - En el campo de filtro de Wireshark, escribe:
     ```
     tcp.flags.syn==1 && tcp.flags.ack==0
     ```
     y presiona Enter.
   - Observa los paquetes SYN enviados desde Kali y la respuesta SYN-ACK del objetivo.
5. Observar el three-way handshake y el TTL para deducir sistema operativo:
   - Usa Wireshark con el filtro:
     ```
     tcp.flags.syn==1 || tcp.flags.ack==1
     ```
   - Identifica las tres fases del handshake TCP:
     1. `SYN` (inicio del cliente)
     2. `SYN-ACK` (respuesta del servidor)
     3. `ACK` (confirmación del cliente)
   - Haz clic en un paquete del servidor (SYN-ACK) o de respuesta, y en la parte inferior busca el campo `Time to live (TTL)`.
   - TTL ≈ 64 → Linux / TTL ≈ 128 → Windows

- Si no ves paquetes SYN-ACK durante el escaneo, puedes forzar una conexión con `netcat` para generar una respuesta observable:
  ```bash
  nc -vz $OBJETIVO 80
  ```
  Luego, en Wireshark, aplica el filtro:
  ```
  tcp.flags.fin==1 && tcp.flags.ack==1
  ```
  y observa el campo `TTL` en el paquete de respuesta. Aunque no es parte del handshake, el TTL sigue revelando información sobre el sistema operativo.

### Solución esperada
- Puertos abiertos detectados como 22 (SSH), 80 (HTTP).
- Captura del handshake (SYN > SYN-ACK > ACK).
- TTL ~64 = Linux, TTL ~128 = Windows.

---

## Laboratorio 2: Escaneo de Puertos y Evasiones

### Objetivo
Realizar escaneos furtivos y evasivos para evitar detección por firewalls o IDS.

### Setup y herramientas
- **VM de Kali Linux**
- **Contenedor víctima**:
  ```bash
  docker run -d -p 80:80 -p 22:22 --name evasive-target vulnerables/web-dvwa
  ```
- Herramientas: `nmap`, `wireshark`

### Instrucciones paso a paso (desde Kali VM)

**Sugerencia útil**: Para facilitar la ejecución de comandos, puedes definir una variable de entorno en Kali con la IP del objetivo:
```bash
export OBJETIVO=192.168.50.187  # Reemplaza con la IP de tu host
```
Luego usa `$OBJETIVO` en lugar de escribir la IP completa:
1. Verifica conectividad:
   ```bash
   ping $OBJETIVO
   ```
2. Ejecuta escaneos con:
   ```bash
   nmap -sX $OBJETIVO
   nmap -sN $OBJETIVO
   nmap -f $OBJETIVO
   nmap -D RND:10 $OBJETIVO
   ```
3. Si deseas simular un entorno con un puerto no accesible, puedes:
   - Opción A: Relanzar el contenedor sin exponer el puerto 80:
     ```bash
     docker stop evasive-target && docker rm evasive-target
     docker run -d -p 22:22 --name evasive-target vulnerables/web-dvwa
     ```
   - Opción B (solo en Windows): Usar el Firewall de Windows para bloquear temporalmente el puerto 80:
     1. Abre el menú Inicio y busca "Firewall de Windows con seguridad avanzada".
     2. Ve a Reglas de entrada > Nueva regla.
     3. Selecciona "Puerto" y haz clic en "Siguiente".
     4. Marca "TCP" y escribe `80` en puertos específicos.
     5. Selecciona "Bloquear la conexión" y completa la creación de la regla.
     6. Realiza el escaneo y luego elimina la regla si lo deseas.

4. Repite escaneo y analiza diferencias en los resultados.

### Solución esperada
- Escaneos furtivos no siempre generan respuesta detectable.
- IP Decoy oculta al origen.
- Fragmentación puede evadir filtros básicos.

---

## Laboratorio 3: Detección de Sistema Operativo y Banner Grabbing

### Objetivo
Determinar el sistema operativo de un host objetivo mediante TTL y captura de banners.

### Setup y herramientas
- **VM de Kali Linux**
- **Contenedor víctima**:
  ```bash
  docker run -d -p 80:80 -p 22:22 --name os-id-target vulnerables/web-dvwa
  ```
- Herramientas: `nmap`, `telnet`, `netcat`, `wireshark`

### Instrucciones paso a paso (desde Kali VM)

**Sugerencia útil**: Puedes usar la misma variable de entorno si ya la definiste:
```bash
export OBJETIVO=192.168.50.187
```

1. Ejecutar escaneo de versión:
   ```bash
   nmap -sS -sV $OBJETIVO
   ```
2. Capturar banner con Netcat:
   ```bash
   nc $OBJETIVO 80
   GET / HTTP/1.1
   Host: $OBJETIVO
   ```
3. Alternativamente, usar Telnet:
   ```bash
   telnet $OBJETIVO 80
   ```
   Si la conexión es exitosa, verás algo como:
   ```
Trying 192.168.x.x...
Connected to 192.168.x.x.
Escape character is '^]'.
   ```
   Esto confirma que el puerto 80 está abierto y recibiendo conexiones TCP, lo que también permite observar el TTL en Wireshark para deducir el sistema operativo.bash
   telnet $OBJETIVO 80
   ```
4. Capturar paquetes con Wireshark:
   - Filtro: `icmp || tcp.analysis.flags`
5. Identificar SO con TTL y versiones de servicios.

### Solución esperada
- TTL ~64 indica Linux; TTL ~128 indica Windows.
- Banner Apache o SSH muestra versión de software y posible distribución.
- `nmap -O` ayuda a confirmar el sistema operativo si no hay firewall.
- Al realizar una conexión manual con Netcat al puerto 80, se obtuvo una respuesta en formato HTML, lo que confirma que el servicio HTTP está activo. El servidor expuso una estructura de carpetas típica de Linux y devolvió un error `403 Forbidden`, indicando que el acceso al contenido está restringido por configuración. Esta información permite confirmar la presencia de un servidor web y sugiere un sistema operativo basado en Linux, reforzado por el TTL observado en Wireshark (~64).
- Banner Apache o SSH muestra versión de software y posible distribución.
- `nmap -O` ayuda a confirmar el sistema operativo si no hay firewall.

---

## Laboratorio Extra (Reto Final)

### Objetivo
Aplicar herramientas de reconocimiento pasivo y activo para analizar la superficie pública de una plataforma web real.

### Enunciado
Como reto final de la clase, elige un sitio web conocido y legal de acceso público (por ejemplo: https://www.netflix.com, https://www.apple.com, https://www.ucr.ac.cr). Realiza un análisis básico de red y servicios con herramientas que no generen carga ofensiva ni vulneración.

### Indicaciones
1. Realiza un escaneo pasivo con:
   ```bash
   whois netflix.com
   nslookup netflix.com
   dig netflix.com
   ```
2. Ejecuta un escaneo superficial con `nmap` sobre uno de sus servidores públicos:
   ```bash
   nmap -sS -p 80,443 -Pn netflix.com
   ```
3. Usa `curl` o `netcat` para hacer un banner grabbing del servidor:
   ```bash
   curl -I https://netflix.com
   # o
   nc netflix.com 80
   GET / HTTP/1.1
   Host: netflix.com
   ```
4. Documenta TTL observado en Wireshark al cargar la página desde un navegador o terminal.

### Resultado esperado
- Información de DNS y dominio (whois, dig, nslookup).
- Puertos abiertos detectados con `nmap`.
- Banner HTTP recibido.
- Valor TTL observado.
- Reflexión sobre el sistema operativo o infraestructura probable (CDN, nube pública, etc.).

---

## Evidencias para campus virtual

- Incluir:
  - Capturas (`/screenshots`)
- Evaluación sugerida:
  - Evidencia de escaneo
  - Captura de TTL o handshake
  - Análisis de resultados y reflexión escrita

---

**Profesor:** Esteban Mata Morales  
**Curso:** CY-203 Hackeo Ético  
**Universidad Fidélitas de Costa Rica**
