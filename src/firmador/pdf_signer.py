import base64
import os
import re
import subprocess
import tempfile


import fitz
from asn1crypto import x509
from pyhanko.sign import signers
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter


PATRON_DNI = re.compile(r"(?<!\d)(\d{8})(?!\d)")
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MENSAJE_IDENTIDAD_FALLIDA = (
    "Validación de identidad fallida. El DNIe insertado no pertenece al "
    "usuario que inició sesión."
)


def leer_certificado_dnie() -> dict:
    """Lee el certificado FIR del DNIe desde Windows CAPI.
    
    El DNIe tiene 2 certificados:
    - CIF (Identificación): keyUsage = digitalSignature
    - FIR (Firma): keyUsage = nonRepudiation  <-- este necesitamos
    """
    import ssl

    try:
        certificados = ssl.enum_certificates("MY")
    except Exception as e:
        raise RuntimeError(f"Error al acceder a Windows CAPI: {str(e)}") from e

    fir_cert = None
    ci_cert = None

    for cert_bytes, encoding, trust in certificados:
        if encoding != "x509_asn":
            continue
        cert = x509.Certificate.load(cert_bytes)
        issuer = cert.issuer.native

        if "RENIEC" not in str(issuer).upper():
            continue

        subject = cert.subject.native
        nombre = str(subject.get("common_name", "")).upper()
        datos = {
            "nombre": _primer_texto(subject.get("common_name")),
            "dni": _normalizar_dni_certificado(
                subject.get("serial_number")
            ),
            "thumbprint": cert.sha1.hex().upper(),
            "cert_bytes": cert_bytes,
        }

        # FIR = Firma (nonRepudiation), CIF = Identificación
        if "FIR" in nombre:
            fir_cert = datos
        else:
            ci_cert = datos

    # Priorizar FIR sobre CIF
    if fir_cert:
        return fir_cert
    if ci_cert:
        return ci_cert

    raise RuntimeError(
        "No se detectó el certificado de la RENIEC en el almacén de Windows. "
        "Inserte el DNIe."
    )


def _sign_via_capi(thumbprint: str, data: bytes) -> bytes:
    """Firma datos usando Windows CAPI vía PowerShell + RSACryptoServiceProvider.
    
    Pasa los datos RAW a PowerShell y usa SignData (hashing + DigestInfo interno).
    """
    data_b64 = base64.b64encode(data).decode()

    # Script PowerShell: SignData maneja hashing y DigestInfo automáticamente
    ps = (
        "$cert = Get-Item \"Cert:\\CurrentUser\\My\\" + thumbprint + "\"\n"
        "$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey\n"
        "$raw = [System.Convert]::FromBase64String(\"" + data_b64 + "\")\n"
        "$sig = $rsa.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, "
        "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
        "Write-Output (\"SIG:\" + [System.Convert]::ToBase64String($sig))\n"
    )

    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True,
        text=True,
        timeout=30,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"PowerShell CAPI signing failed: {result.stderr.strip()}"
        )

    for line in result.stdout.splitlines():
        if line.startswith("SIG:"):
            return base64.b64decode(line[4:])

    raise RuntimeError(
        f"No signature in PowerShell output: {result.stdout[:200]}"
    )


class WindowsCAPISigner(signers.Signer):
    """Signer que usa Windows CAPI (RSACryptoServiceProvider) para firmar.
    
    Ejecuta PowerShell internamente para acceder a la CSP del DNIe.
    """

    def __init__(self, thumbprint: str, cert_bytes: bytes):
        self._thumbprint = thumbprint
        self._cert = x509.Certificate.load(cert_bytes)
        super().__init__(
            signature_mechanism=None,  # auto-detect
            prefer_pss=False,
            embed_roots=True,
            signing_cert=self._cert,
        )

    @property
    def signing_cert(self):
        return self._cert

    async def async_sign_raw(
        self, data: bytes, digest_algorithm: str = "sha256", dry_run: bool = False
    ) -> bytes:
        if dry_run:
            # Devolver firma dummy para estimación de tamaño
            return b"\x00" * 256
        return _sign_via_capi(self._thumbprint, data)


def firmar_pdf(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    return firmar_documento(pdf_base64, pin, dni_esperado)


def firmar_documento(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")

    dni_esperado = _normalizar_dni(dni_esperado)

    # Leer certificado desde Windows CAPI (funciona)
    datos_identidad = leer_certificado_dnie()
    _validar_identidad_dnie(datos_identidad, dni_esperado)

    pdf_bytes = _decodificar_pdf(pdf_base64)
    thumbprint = datos_identidad["thumbprint"]
    cert_bytes = datos_identidad["cert_bytes"]

    try:
        with tempfile.TemporaryDirectory(prefix="firma_dnie_") as temp_dir:
            ruta_pdf_entrada = os.path.join(temp_dir, "temp_in.pdf")
            ruta_pdf_normalizado = os.path.join(temp_dir, "temp_in_norm.pdf")
            ruta_pdf_firmado = os.path.join(temp_dir, "temp_in_firmado.pdf")

            with open(ruta_pdf_entrada, "wb") as f:
                f.write(pdf_bytes)

            # Normalizar PDF a v1.7
            _normalizar_pdf(ruta_pdf_entrada, ruta_pdf_normalizado)

            # Crear signer CAPI y firmar con pyHanko
            signer = WindowsCAPISigner(thumbprint, cert_bytes)

            with open(ruta_pdf_normalizado, "rb") as f:
                w = IncrementalPdfFileWriter(f)

                with open(ruta_pdf_firmado, "wb") as pdf_out:
                    # sign_pdf ya maneja asyncio.run() internamente
                    signers.sign_pdf(
                        w,
                        signature_meta=signers.PdfSignatureMetadata(
                            field_name="Signature1",
                            subfilter=SigSeedSubFilter.PADES,
                            reason="Firma digital con DNIe",
                        ),
                        signer=signer,
                        output=pdf_out,
                        existing_fields_only=False,
                    )

            with open(ruta_pdf_firmado, "rb") as f:
                pdf_firmado = f.read()

        return {
            "pdf_firmado": base64.b64encode(pdf_firmado).decode("ascii"),
            "dni_extraido": datos_identidad.get("dni"),
            "nombre_firmante": datos_identidad.get("nombre"),
        }
    except Exception as exc:
        raise RuntimeError(_describir_error_firma(exc)) from exc


# ---------------------------------------------------------------------------
# Funciones auxiliares
# ---------------------------------------------------------------------------


def _normalizar_pdf(ruta_entrada: str, ruta_salida: str):
    """Convierte PDF a versión 1.7 (necesario para firmas digitales)."""
    with fitz.open(ruta_entrada) as doc:
        doc.save(ruta_salida, garbage=4, deflate=True, clean=True)
    # Forzar versión 1.7 en el header del PDF
    with open(ruta_salida, "rb") as f:
        content = f.read()
    content = re.sub(rb"%PDF-\d\.\d", b"%PDF-1.7", content, count=1)
    with open(ruta_salida, "wb") as f:
        f.write(content)


def _decodificar_pdf(pdf_base64: str) -> bytes:
    try:
        return base64.b64decode(pdf_base64)
    except (binascii.Error, ValueError, TypeError) as e:
        raise ValueError(f"PDF en Base64 inválido: {str(e)}") from e


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
    return mensaje or "No se pudo firmar el PDF"
