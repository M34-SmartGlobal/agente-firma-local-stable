import base64
import binascii
import os
import re
import ssl
import subprocess
import tempfile

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


def firmar_documento(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")

    dni_esperado = _normalizar_dni(dni_esperado)
    datos_identidad = leer_certificado_dnie()
    _validar_identidad_dnie(datos_identidad, dni_esperado)

    pdf_bytes = _decodificar_pdf(pdf_base64)
    ruta_ejecutable = os.path.join(BASE_DIR, "motor_java", "JSignPdfC.exe")
    if not os.path.exists(ruta_ejecutable):
        raise FileNotFoundError(
            f"No se encontró el ejecutable nativo de firma: {ruta_ejecutable}"
        )

    try:
        with tempfile.TemporaryDirectory(prefix="firma_dnie_") as temp_dir:
            ruta_pdf_entrada = os.path.join(temp_dir, "temp_in.pdf")
            ruta_salida_dir = os.path.join(temp_dir, "salida")
            os.makedirs(ruta_salida_dir, exist_ok=True)

            with open(ruta_pdf_entrada, "wb") as archivo_pdf:
                archivo_pdf.write(pdf_bytes)

            comando = [
                ruta_ejecutable,
                "-kst",
                "WINDOWS-MY",
                "-a",
                "-d",
                ruta_salida_dir,
                ruta_pdf_entrada,
            ]
            resultado = subprocess.run(
                comando,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if resultado.returncode != 0:
                detalle_error = (resultado.stderr or resultado.stdout or "").strip()
                raise RuntimeError(
                    "JSignPdf no pudo firmar el documento"
                    + (f": {detalle_error}" if detalle_error else "")
                )

            ruta_pdf_firmado = os.path.join(ruta_salida_dir, "temp_in_signed.pdf")
            if not os.path.exists(ruta_pdf_firmado):
                raise RuntimeError(
                    "JSignPdf finalizó sin generar el archivo temp_in_signed.pdf"
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
