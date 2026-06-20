import base64
import binascii
import datetime
import re

from asn1crypto import x509
from endesive import pdf
from win32.lib import win32cryptcon

try:
    from win32 import win32crypt
except ImportError:
    import win32crypt


PATRON_DNI = re.compile(r"(?<!\d)(\d{8})(?!\d)")
MENSAJE_IDENTIDAD_FALLIDA = (
    "Validación de identidad fallida. El DNIe insertado no pertenece al "
    "usuario que inició sesión."
)
CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x10000
ALGORITMOS_HASH_CAPI = {
    "sha1": getattr(win32cryptcon, "CALG_SHA1", 0x00008004),
    "sha256": getattr(win32cryptcon, "CALG_SHA_256", 0x0000800C),
    "sha384": getattr(win32cryptcon, "CALG_SHA_384", 0x0000800D),
    "sha512": getattr(win32cryptcon, "CALG_SHA_512", 0x0000800E),
}


class WindowsCAPIRENIECHSM:
    def __init__(self, dni_esperado: str):
        self.certificado = None
        self.certificado_der = None
        self.datos_identidad = None
        self._seleccionar_certificado_reniec(dni_esperado)

    def _seleccionar_certificado_reniec(self, dni_esperado: str):
        store = win32crypt.CertOpenSystemStore("MY", None)
        try:
            for certificado in store.CertEnumCertificatesInStore():
                certificado_der = certificado.CertEncoded
                datos_identidad = _extraer_datos_certificado(certificado_der)

                if "RENIEC" not in str(datos_identidad.get("issuer", "")).upper():
                    continue

                _validar_identidad_dnie(datos_identidad, dni_esperado)
                self.certificado = certificado
                self.certificado_der = certificado_der
                self.datos_identidad = datos_identidad
                return
        finally:
            store.CertCloseStore()

        raise RuntimeError(
            "No se detectó un certificado RENIEC con llave privada en el almacén "
            "Windows MY. Inserte el DNIe."
        )

    def certificate(self):
        return 1, self.certificado_der

    def sign(self, keyid, data, mech):
        algoritmo = str(mech or "sha256").lower().replace("-", "")
        algoritmo_capi = ALGORITMOS_HASH_CAPI.get(algoritmo)
        if algoritmo_capi is None:
            raise RuntimeError(f"Algoritmo de firma no soportado por MSCAPI: {mech}")

        flags = (
            win32cryptcon.CRYPT_ACQUIRE_COMPARE_KEY_FLAG
            | CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG
        )
        keyspec, cryptprov = self.certificado.CryptAcquireCertificatePrivateKey(flags)
        hash_capi = cryptprov.CryptCreateHash(algoritmo_capi, None, 0)
        hash_capi.CryptHashData(data, 0)
        firma = hash_capi.CryptSignHash(keyspec, 0)
        return firma[::-1]


def firmar_pdf(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")

    dni_esperado = _normalizar_dni(dni_esperado)
    pdf_bytes = _decodificar_pdf(pdf_base64)

    try:
        hsm = WindowsCAPIRENIECHSM(dni_esperado)
        fecha_firma = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
        metadatos_firma = {
            "sigflags": 3,
            "contact": "MASGLOBAL",
            "location": "Perú",
            "signingdate": fecha_firma.strftime("D:%Y%m%d%H%M%S+00'00'").encode(),
            "reason": "Firma digital con DNIe vía Windows CAPI",
            "signaturebox": (50, 50, 280, 115),
        }

        firma = pdf.cms.sign(
            pdf_bytes,
            metadatos_firma,
            None,
            None,
            [],
            "sha256",
            hsm,
        )
        pdf_firmado = pdf_bytes + firma

        return {
            "pdf_firmado": base64.b64encode(pdf_firmado).decode("ascii"),
            "dni_extraido": hsm.datos_identidad.get("dni"),
            "nombre_firmante": hsm.datos_identidad.get("nombre_firmante"),
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


def _extraer_datos_certificado(certificado_der):
    certificado_x509 = x509.Certificate.load(certificado_der)
    subject = certificado_x509.subject
    subject_native = subject.native or {}
    issuer = certificado_x509.issuer.native or {}

    nombre_firmante = _primer_texto(subject_native.get("common_name"))
    textos_prioritarios = [
        subject_native.get("serial_number"),
        subject_native.get("common_name"),
        subject_native.get("dn_qualifier"),
    ]
    textos_generales = _extraer_textos(subject_native)
    dni = _buscar_dni(textos_prioritarios) or _buscar_dni(textos_generales)

    return {
        "dni": dni,
        "nombre_firmante": nombre_firmante,
        "subject": subject.human_friendly,
        "issuer": issuer,
    }


def _normalizar_dni(dni: str) -> str:
    dni_normalizado = re.sub(r"\D", "", str(dni or ""))
    if len(dni_normalizado) != 8:
        raise ValueError("Debe enviar un DNI esperado válido de 8 dígitos")
    return dni_normalizado


def _validar_identidad_dnie(datos_identidad: dict, dni_esperado: str):
    dni_extraido = datos_identidad.get("dni")
    if dni_extraido and dni_extraido != dni_esperado:
        raise PermissionError(MENSAJE_IDENTIDAD_FALLIDA)
    if not dni_extraido:
        raise RuntimeError("No se pudo extraer el DNI del certificado RENIEC")


def _buscar_dni(textos) -> str | None:
    for texto in _extraer_textos(textos):
        coincidencia = PATRON_DNI.search(texto)
        if coincidencia:
            return coincidencia.group(1)
    return None


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
    if "SCARD" in mensaje_mayusculas or "SMART CARD" in mensaje_mayusculas:
        return "DNIe no insertado o lector no detectado"
    if "PIN" in mensaje_mayusculas:
        return "PIN incorrecto o cancelado por el usuario"
    if "WINDOWS CAPI" in mensaje_mayusculas or "MSCAPI" in mensaje_mayusculas:
        return mensaje

    return mensaje or "No se pudo firmar el PDF"
