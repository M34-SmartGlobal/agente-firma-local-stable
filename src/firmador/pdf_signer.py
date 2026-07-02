import base64
import binascii
import os
import re
import ssl
import subprocess
import tempfile

import fitz
from asn1crypto import x509


PATRON_DNI = re.compile(r"(?<!\d)(\d{8})(?!\d)")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MENSAJE_IDENTIDAD_FALLIDA = (
    "Validación de identidad fallida. El DNIe insertado no pertenece al "
    "usuario que inició sesión."
)


def leer_certificado_dnie() -> dict:
    try:
        certificados = ssl.enum_certificates("MY")
    except Exception as exc:
        raise RuntimeError(f"Error al acceder a Windows CAPI: {str(exc)}") from exc

    for cert_bytes, encoding, trust in certificados:
        if encoding != "x509_asn":
            continue

        cert = x509.Certificate.load(cert_bytes)
        issuer = cert.issuer.native

        if "RENIEC" in str(issuer).upper():
            subject = cert.subject.native
            return {
                "nombre": _primer_texto(subject.get("common_name")),
                "dni": _normalizar_dni_certificado(subject.get("serial_number")),
            }

    raise RuntimeError(
        "No se detectó el certificado de la RENIEC en el almacén de Windows. "
        "Inserte el DNIe."
    )


def firmar_pdf(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    return firmar_documento(pdf_base64, pin, dni_esperado)


def _comando_java():
    import shutil
    # 1. JAVA_HOME
    jh = os.environ.get("JAVA_HOME") or os.environ.get("JDK_HOME")
    if jh:
        jbin = os.path.join(jh, "bin", "java.exe")
        if os.path.exists(jbin):
            return jbin
    # 2. shutil.which (PATH del sistema)
    java = shutil.which("java")
    if java:
        return java
    # 3. Rutas tipicas de Oracle JDK 21
    rutas = [
        r"C:\Program Files\Java\jdk-21\bin\java.exe",
        r"C:\Program Files\Java\jdk-21.0.10\bin\java.exe",
        r"C:\Program Files\Java\jre-21.0.10\bin\java.exe",
        r"C:\Program Files\Java\jdk-21.0.10+8\bin\java.exe",
    ]
    for r in rutas:
        if os.path.exists(r):
            return r
    # 4. where java via cmd
    try:
        r = subprocess.run(["where", "java"], capture_output=True, text=True, timeout=3)
        res = r.stdout.strip().splitlines()
        return res[0] if res else "java"
    except Exception:
        return "java"


def _buscar_dll_pkcs11():
    """Busca la DLL PKCS#11 del DNIe (OpenSC o Bit4id)."""
    rutas = [
        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\onepin-opensc-pkcs11.dll",
        r"C:\Windows\System32\opensc-pkcs11.dll",
        r"C:\Windows\System32\bit4xpki64.dll",
        r"C:\Windows\System32\bit4xpki.dll",
    ]
    for ruta in rutas:
        if os.path.exists(ruta):
            return ruta
    raise RuntimeError(
        "No se encontró ninguna DLL PKCS#11. "
        "Instale OpenSC o los drivers del DNIe."
    )


def firmar_documento(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")

    dni_esperado = _normalizar_dni(dni_esperado)
    datos_identidad = leer_certificado_dnie()
    _validar_identidad_dnie(datos_identidad, dni_esperado)

    pdf_bytes = _decodificar_pdf(pdf_base64)
    ruta_java = _comando_java()
    ruta_jar = os.path.join(BASE_DIR, "motor_java", "app", "JSignPdf.jar")
    ruta_installcert = os.path.join(BASE_DIR, "motor_java", "app", "InstallCert.jar")
    ruta_dll = _buscar_dll_pkcs11()

    try:
        with tempfile.TemporaryDirectory(prefix="firma_dnie_") as temp_dir:
            ruta_pdf_entrada = os.path.join(temp_dir, "temp_in.pdf")
            ruta_salida_dir = os.path.join(temp_dir, "salida")
            os.makedirs(ruta_salida_dir, exist_ok=True)

            with open(ruta_pdf_entrada, "wb") as archivo_pdf:
                archivo_pdf.write(pdf_bytes)

            ruta_pdf_normalizado = _normalizar_pdf(ruta_pdf_entrada)

            # Config PKCS#11
            ruta_pkcs11_cfg = os.path.join(temp_dir, "pkcs11.cfg")
            with open(ruta_pkcs11_cfg, "w") as f:
                f.write(f"name = OpenSC\n")
                f.write(f"library = {ruta_dll.replace(chr(92), '/')}\n")

            override_security = os.path.join(
                BASE_DIR, "motor_java", "app", "pkcs11_override.security"
            )

            comando = [
                ruta_java,
                "--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11=ALL-UNNAMED",
                "--add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED",
                "--add-exports=java.base/sun.security.action=ALL-UNNAMED",
                "--add-exports=java.base/sun.security.rsa=ALL-UNNAMED",
                "--add-opens=java.base/sun.security.util=ALL-UNNAMED",
                f"-Dpkcs11.cfg.path={ruta_pkcs11_cfg.replace(chr(92), '/')}",
                f"-Djava.security.properties={override_security.replace(chr(92), '/')}",
                "-cp",
                f"{ruta_jar};{ruta_installcert}",
                "net.sf.jsignpdf.Signer",
                "-kst",
                "PKCS11",
                "-ksp",
                "PASSWORD_PROMPT",
                "-ha",
                "SHA512",
                "-d",
                ruta_salida_dir,
                ruta_pdf_normalizado,
            ]
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if resultado.returncode != 0:
                raise RuntimeError(
                    "JSignPdf no pudo firmar el documento. "
                    f"Código de salida: {resultado.returncode}. "
                    f"STDERR: {(resultado.stderr or '').strip()} "
                    f"STDOUT: {(resultado.stdout or '').strip()}"
                )

            # Buscar PDF firmado (cambia segun nombre del input)
            posibles = [os.path.join(ruta_salida_dir, f) for f in os.listdir(ruta_salida_dir)]
            pdfs = [f for f in posibles if f.endswith(".pdf")]
            if pdfs:
                ruta_pdf_firmado = pdfs[0]
            else:
                raise RuntimeError(
                    "JSignPdf finalizó sin generar PDF firmado. "
                    f"Contenido: {os.listdir(ruta_salida_dir)} "
                    f"STDOUT: {(resultado.stdout or '').strip()}"
                )

            with open(ruta_pdf_firmado, "rb") as archivo_firmado:
                pdf_firmado = archivo_firmado.read()

        return {
            "pdf_firmado": base64.b64encode(pdf_firmado).decode("ascii"),
            "dni_extraido": datos_identidad.get("dni"),
            "nombre_firmante": datos_identidad.get("nombre"),
        }
    except Exception as exc:
        raise RuntimeError(_describir_error_firma(exc)) from exc


def _normalizar_pdf(ruta_entrada):
    doc = fitz.open(ruta_entrada)
    ruta_salida = ruta_entrada.replace(".pdf", "_norm.pdf")

    nuevo_doc = fitz.open()
    nuevo_doc.insert_pdf(doc)

    nuevo_doc.pdf_version = "1.7"
    nuevo_doc.save(ruta_salida, garbage=4, deflate=True, clean=True)

    doc.close()
    nuevo_doc.close()

    return ruta_salida


def _decodificar_pdf(pdf_base64: str) -> bytes:
    contenido = pdf_base64.split(",", 1)[1] if "," in pdf_base64 else pdf_base64
    try:
        pdf_bytes = base64.b64decode(contenido, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("El PDF recibido no es Base64 válido") from exc

    if not pdf_bytes.startswith(b"%PDF"):
        raise ValueError("El archivo recibido no parece ser un PDF válido")
    return pdf_bytes


def _normalizar_dni(dni: str) -> str:
    dni_normalizado = re.sub(r"\D", "", str(dni or ""))
    if len(dni_normalizado) != 8:
        raise ValueError("Debe enviar un DNI esperado válido de 8 dígitos")
    return dni_normalizado


def _normalizar_dni_certificado(valor) -> str | None:
    for texto in _extraer_textos(valor):
        coincidencia = PATRON_DNI.search(texto)
        if coincidencia:
            return coincidencia.group(1)
    return None


def _validar_identidad_dnie(datos_identidad: dict, dni_esperado: str):
    dni_extraido = datos_identidad.get("dni")
    if dni_extraido and dni_extraido != dni_esperado:
        raise PermissionError(MENSAJE_IDENTIDAD_FALLIDA)
    if not dni_extraido:
        raise RuntimeError("No se pudo extraer el DNI del certificado RENIEC")


def _extraer_textos(valor):
    if valor is None:
        return []
    if isinstance(valor, (list, tuple, set)):
        textos = []
        for item in valor:
            textos.extend(_extraer_textos(item))
        return textos
    if isinstance(valor, dict):
        textos = []
        for item in valor.values():
            textos.extend(_extraer_textos(item))
        return textos
    return [str(valor)]


def _primer_texto(valor):
    textos = _extraer_textos(valor)
    return textos[0] if textos else None


def _describir_error_firma(exc: Exception) -> str:
    mensaje = str(exc)
    mensaje_mayusculas = mensaje.upper()

    if MENSAJE_IDENTIDAD_FALLIDA.upper() in mensaje_mayusculas:
        return MENSAJE_IDENTIDAD_FALLIDA
    if "JAVA" in mensaje_mayusculas and "NOT FOUND" in mensaje_mayusculas:
        return "Java no está instalado o no está disponible en el PATH"
    if "JSIGNPDF" in mensaje_mayusculas:
        return mensaje
    if "WINDOWS CAPI" in mensaje_mayusculas or "WINDOWS-MY" in mensaje_mayusculas:
        return mensaje

    return mensaje or "No se pudo firmar el PDF"
