import base64
import io
import os
import re
import tempfile

import fitz
from asn1crypto import x509
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter, SigFieldSpec
from pyhanko.sign.pkcs11 import open_pkcs11_session, PKCS11Signer
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pkcs11 import TokenException


PATRON_DNI = re.compile(r"(?<!\d)(\d{8})(?!\d)")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MENSAJE_IDENTIDAD_FALLIDA = (
    "Validaci\u00f3n de identidad fallida. El DNIe insertado no pertenece al "
    "usuario que inici\u00f3 sesi\u00f3n."
)


def _buscar_dll_pkcs11() -> str:
    """Busca la DLL PKCS#11 del DNIe (Bit4id tiene prioridad sobre OpenSC)."""
    rutas = [
        # Bit4id (DLL oficial del DNIe peruano)
        r"C:\Windows\System32\bit4xpki64.dll",
        r"C:\Windows\System32\bit4xpki.dll",
        r"C:\Program Files\Bit4id\bit4xpki.dll",
        r"C:\Program Files (x86)\Bit4id\bit4xpki.dll",
        # OpenSC (fallback)
        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll",
        r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\onepin-opensc-pkcs11.dll",
        r"C:\Windows\System32\opensc-pkcs11.dll",
    ]
    for ruta in rutas:
        if os.path.exists(ruta):
            return ruta
    raise RuntimeError(
        "No se encontr\u00f3 ninguna DLL PKCS#11. "
        "Instale los drivers del DNIe (Bit4id) u OpenSC."
    )


def leer_certificado_dnie_pkcs11(pin: str) -> dict:
    """Lee el certificado del DNIe directamente desde la tarjeta v\u00eda PKCS#11.
    
    Args:
        pin: PIN del DNIe.
    
    Returns:
        Dict con 'nombre', 'dni' del titular.
    """
    dll = _buscar_dll_pkcs11()
    try:
        with open_pkcs11_session(
            lib_location=dll,
            slot_no=0,
            user_pin=pin,
        ) as session:
            certs = session.get_objects(
                {session.token.classes.CERTIFICATE}
            )
            for cert_obj in certs:
                raw = bytes(cert_obj.value)
                cert = x509.Certificate.load(raw)
                issuer = cert.issuer.native
                subject = cert.subject.native
                if "RENIEC" in str(issuer).upper():
                    return {
                        "nombre": _primer_texto(subject.get("common_name")),
                        "dni": _normalizar_dni_certificado(
                            subject.get("serial_number")
                        ),
                    }
            raise RuntimeError(
                "No se encontr\u00f3 certificado de la RENIEC en el DNIe."
            )
    except TokenException as e:
        raise RuntimeError(
            f"Error al acceder al DNIe v\u00eda PKCS#11: {str(e)}"
        ) from e


def firmar_pdf(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    return firmar_documento(pdf_base64, pin, dni_esperado)


def firmar_documento(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")

    dni_esperado = _normalizar_dni(dni_esperado)

    # Leer certificado desde PKCS#11 (no Windows CAPI)
    datos_identidad = leer_certificado_dnie_pkcs11(pin)
    _validar_identidad_dnie(datos_identidad, dni_esperado)

    pdf_bytes = _decodificar_pdf(pdf_base64)
    dll = _buscar_dll_pkcs11()

    try:
        with tempfile.TemporaryDirectory(prefix="firma_dnie_") as temp_dir:
            ruta_pdf_entrada = os.path.join(temp_dir, "temp_in.pdf")
            ruta_pdf_normalizado = os.path.join(temp_dir, "temp_in_norm.pdf")
            ruta_pdf_firmado = os.path.join(temp_dir, "temp_in_firmado.pdf")

            with open(ruta_pdf_entrada, "wb") as f:
                f.write(pdf_bytes)

            # Normalizar PDF a v1.7
            _normalizar_pdf(ruta_pdf_entrada, ruta_pdf_normalizado)

            # Firmar con pyHanko + python-pkcs11 (Bit4id)
            with open_pkcs11_session(
                lib_location=dll,
                slot_no=0,
                user_pin=pin,
            ) as session:
                signer = PKCS11Signer(
                    pkcs11_session=session,
                    cert_label=None,  # auto-detect
                    key_label=None,   # auto-detect
                    prefer_pss=False,
                )

                with open(ruta_pdf_normalizado, "rb") as f:
                    w = IncrementalPdfFileWriter(f)
                    signers.sign_pdf(
                        w,
                        signature_meta=signers.PdfSignatureMetadata(
                            field_name="Signature1",
                            subfilter=SigSeedSubFilter.PADES,
                            reason="Firma digital con DNIe",
                        ),
                        signer=signer,
                        output=ruta_pdf_firmado,
                    )

            with open(ruta_pdf_firmado, "rb") as f:
                pdf_firmado = f.read()

        return {
            "pdf_firmado": base64.b64encode(pdf_firmado).decode("ascii"),
            "dni_extraido": datos_identidad.get("dni"),
            "nombre_firmante": datos_identidad.get("nombre"),
        }
    except TokenException as e:
        raise RuntimeError(
            f"Error con la tarjeta DNIe: {str(e)}. "
            "Verifique que el DNIe est\u00e9 insertado y el PIN sea correcto."
        ) from e
    except Exception as exc:
        raise RuntimeError(_describir_error_firma(exc)) from exc


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------

def _normalizar_pdf(ruta_entrada: str, ruta_salida: str):
    """Convierte PDF a versi\u00f3n 1.7 (necesario para firmas digitales)."""
    with fitz.open(ruta_entrada) as doc:
        doc.save(
            ruta_salida,
            pdf_version="1.7",
            garbage=4,
            deflate=True,
            clean=True,
        )


def _decodificar_pdf(pdf_base64: str) -> bytes:
    try:
        return base64.b64decode(pdf_base64)
    except (binascii.Error, ValueError, TypeError) as e:
        raise ValueError(f"PDF en Base64 inv\u00e1lido: {str(e)}") from e


def _normalizar_dni(dni: str) -> str:
    if not dni:
        return dni
    solo_numeros = re.sub(r"\D", "", str(dni))
    if solo_numeros and len(solo_numeros) >= 8:
        return solo_numeros[:8]
    return dni


def _normalizar_dni_certificado(valor) -> str | None:
    if valor is None:
        return None
    textos = _extraer_textos(valor)
    if not textos:
        return None
    return _normalizar_dni(textos[0])


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
    if "PIN" in mensaje_mayusculas and ("INCORRECTO" in mensaje_mayusculas or "INVALID" in mensaje_mayusculas):
        return "PIN del DNIe incorrecto. Verifique e intente nuevamente."
    if "TOKEN" in mensaje_mayusculas and "NOT RECOGNIZED" in mensaje_mayusculas:
        return "El DNIe no es reconocido. Verifique la inserci\u00f3n y los drivers."
    return mensaje or "No se pudo firmar el PDF"
