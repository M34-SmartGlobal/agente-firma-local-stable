# Motor Criptográfico de Firma PAdES - MASGLOBAL

## Descripción

El Motor Criptográfico de Firma PAdES - MASGLOBAL es un agente local de escritorio diseñado para actuar como puente seguro entre el CRM web corporativo y el DNI electrónico peruano. La aplicación combina un servidor local Flask con una interfaz gráfica moderna basada en CustomTkinter para permitir la firma digital de documentos laborales en formato PDF usando el estándar PKCS#11 y firmas PAdES.

El agente se ejecuta en la estación de trabajo del usuario, accede al lector USB de tarjetas inteligentes, valida la presencia del DNIe y utiliza el certificado criptográfico almacenado en el chip para firmar documentos PDF. La interacción con el token criptográfico se realiza a través de OpenSC y la biblioteca PKCS#11 expuesta por `opensc-pkcs11.dll`.

La solución está orientada a procesos internos de Recursos Humanos, con foco en operación local, trazabilidad, validación de identidad y reducción de fricción para usuarios finales.

## Arquitectura

La aplicación se compone de tres capas principales:

1. Interfaz gráfica local: ventana de escritorio desarrollada con CustomTkinter, con indicador de estado del servidor local y monitoreo periódico del lector USB/DNIe.
2. API local Flask: servidor HTTP ejecutado en segundo plano en `localhost:5000`, accesible únicamente desde el equipo del usuario.
3. Motor criptográfico: módulos Python responsables de comunicarse con OpenSC/PKCS#11, leer certificados del DNIe, validar identidad y generar firmas digitales PAdES sobre documentos PDF.

El CRM web se comunica con el agente local usando HTTP contra el puerto local configurado. El endpoint principal de firma es:

```http
POST http://localhost:5000/api/dnie/firmar
```

Payload esperado:

```json
{
  "pdf_base64": "<documento_pdf_en_base64>",
  "pin": "123456",
  "dni_esperado": "76354306"
}
```

Respuesta exitosa:

```json
{
  "status": "success",
  "pdf_firmado": "<documento_pdf_firmado_en_base64>",
  "dni_extraido": "76354306",
  "nombre_firmante": "NOMBRE DEL TITULAR"
}
```

La API también expone endpoints auxiliares para diagnóstico:

```http
GET http://localhost:5000/status
GET http://localhost:5000/api/dnie/status
```

La política CORS está restringida al origen autorizado del CRM:

```text
https://nuevo-crm-rrhh.pages.dev
```

## Requisitos Previos

Antes de ejecutar o compilar la aplicación en Windows, la estación de trabajo debe contar con los siguientes componentes instalados:

1. Python 3.10 o superior: recomendado usar Python oficial para Windows, incluyendo soporte para Tkinter.
2. OpenSC: requerido para exponer la interfaz PKCS#11 del lector y del DNIe.
3. Librería PKCS#11 de OpenSC: ruta esperada por defecto:

```text
C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll
```

4. Lector de tarjetas inteligentes compatible con CCID: conectado por USB y reconocido por Windows.
5. Drivers de tarjetas inteligentes: controladores del lector y servicios Smart Card activos en Windows.
6. DNIe peruano operativo: tarjeta insertada correctamente y PIN de usuario disponible.
7. Microsoft Visual C++ Redistributable: puede ser requerido por dependencias criptográficas en algunos entornos Windows.

## Estructura del Proyecto

```text
.
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
└── src/
    └── firmador/
        ├── __init__.py
        ├── pkcs11_handler.py
        └── pdf_signer.py
```

Componentes principales:

```text
app.py
```

Punto de entrada de la aplicación. Inicializa la GUI, levanta Flask en un hilo secundario y define los endpoints locales consumidos por el CRM.

```text
src/firmador/pkcs11_handler.py
```

Módulo de detección de hardware. Valida la existencia de OpenSC y verifica si existe un token PKCS#11 presente en el lector.

```text
src/firmador/pdf_signer.py
```

Motor de firma. Decodifica PDFs Base64, abre sesión PKCS#11, extrae certificado del DNIe, valida identidad del titular y genera la firma PAdES con pyHanko.

## Instrucciones de Desarrollo en Windows

Abrir PowerShell en la carpeta raíz del proyecto y ejecutar:

```powershell
py -3.10 -m venv venv_win
```

Activar el entorno virtual:

```powershell
.\venv_win\Scripts\Activate.ps1
```

Actualizar herramientas base:

```powershell
python -m pip install --upgrade pip setuptools wheel
```

Instalar dependencias:

```powershell
pip install -r requirements.txt
```

Ejecutar la aplicación en modo desarrollo:

```powershell
python app.py
```

Una vez iniciada, la ventana del agente mostrará el estado del servidor local y el estado del lector USB. El CRM podrá comunicarse con el agente en:

```text
http://localhost:5000
```

## Pruebas Manuales Básicas

Verificar que el agente está encendido:

```powershell
curl http://localhost:5000/status
```

Verificar estado del DNIe:

```powershell
curl http://localhost:5000/api/dnie/status
```

La prueba de firma requiere un PDF en Base64, un DNIe insertado, el PIN correcto y el DNI esperado del usuario autenticado en el CRM.

## Instrucciones de Compilación con PyInstaller

Instalar PyInstaller en el entorno virtual:

```powershell
pip install pyinstaller
```

Compilar como aplicación de escritorio sin consola:

```powershell
pyinstaller --onefile --windowed --name "MotorCriptograficoMASGLOBAL" app.py
```

El ejecutable generado quedará en:

```text
dist\MotorCriptograficoMASGLOBAL.exe
```

Para ambientes corporativos, se recomienda validar el ejecutable en una estación Windows con OpenSC, lector CCID, drivers del lector y DNIe real antes de su distribución masiva.

## Consideraciones de Seguridad

El agente debe ejecutarse únicamente en equipos corporativos autorizados.

El PIN del DNIe nunca debe persistirse en disco ni registrarse en logs.

La validación de identidad compara el DNI esperado por el CRM contra el DNI extraído del certificado público del token antes de firmar.

El servidor local está limitado a `127.0.0.1` y usa CORS restringido al dominio del CRM autorizado.

La distribución final debe acompañarse de controles internos de instalación, versionado y hash del ejecutable.

## Uso Corporativo

Esta aplicación es de uso corporativo estrictamente privado y propiedad exclusiva de MASGLOBAL. Su uso, copia, modificación o distribución fuera de los procesos autorizados está prohibido.
