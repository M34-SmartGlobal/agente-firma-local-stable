import base64
import binascii
import re
from io import BytesIO
from pathlib import Path

from asn1crypto import x509
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.stamp import TextStampStyle


OPENSC_PKCS11_DLL = Path(
    r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
)
SIGNATURE_FIELD_NAME = "FirmaDNIe"
PATRON_DNI = re.compile(r"(?<!\d)(\d{8})(?!\d)")
MENSAJE_IDENTIDAD_FALLIDA = (
    "Validación de identidad fallida. El DNIe insertado no pertenece al "
    "usuario que inició sesión."
)


def firmar_pdf(pdf_base64: str, pin: str, dni_esperado: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")
    if not pin:
        raise ValueError("Debe enviar el PIN del DNIe")
    dni_esperado = _normalizar_dni(dni_esperado)
    if not OPENSC_PKCS11_DLL.exists():
        raise FileNotFoundError("OpenSC no está instalado")

    pdf_bytes = _decodificar_pdf(pdf_base64)

    try:
        from pyhanko.sign import pkcs11 as pyhanko_pkcs11
    except ModuleNotFoundError as exc:
        if exc.name == "pkcs11":
            raise RuntimeError(
                "Falta la dependencia python-pkcs11. Ejecute pip install -r requirements.txt"
            ) from exc
        raise

    try:
        with pyhanko_pkcs11.open_pkcs11_session(
            str(OPENSC_PKCS11_DLL), user_pin=pin
        ) as session:
            credenciales = _seleccionar_credenciales_firma(session)
            datos_identidad = credenciales.get("datos_identidad") or {}
            _validar_identidad_dnie(datos_identidad, dni_esperado)

            signer = pyhanko_pkcs11.PKCS11Signer(
                pkcs11_session=session,
                cert_id=credenciales.get("cert_id"),
                key_id=credenciales.get("key_id"),
                cert_label=credenciales.get("cert_label"),
                key_label=credenciales.get("key_label"),
                other_certs_to_pull=None,
            )

            pdf_writer = IncrementalPdfFileWriter(BytesIO(pdf_bytes))
            output = BytesIO()

            pdf_signer = signers.PdfSigner(
                signers.PdfSignatureMetadata(
                    field_name=SIGNATURE_FIELD_NAME,
                    md_algorithm="sha256",
                    subfilter=fields.SigSeedSubFilter.PADES,
                    reason="Firma digital con DNIe",
                ),
                signer=signer,
                stamp_style=TextStampStyle(
                    stamp_text="Firmado digitalmente con DNIe\n%(ts)s"
                ),
                new_field_spec=fields.SigFieldSpec(
                    sig_field_name=SIGNATURE_FIELD_NAME,
                    on_page=0,
                    box=(50, 50, 280, 115),
                ),
            )
            firmado = pdf_signer.sign_pdf(pdf_writer, output=output)

            return {
                "pdf_firmado": base64.b64encode(firmado.getvalue()).decode("ascii"),
                "dni_extraido": datos_identidad.get("dni"),
                "nombre_firmante": datos_identidad.get("nombre_firmante"),
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


def _seleccionar_credenciales_firma(session):
    from pkcs11 import Attribute, ObjectClass

    certificados = list(
        session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})
    )
    if not certificados:
        raise RuntimeError("No se encontró ningún certificado en el DNIe")

    candidatos = sorted(
        (_credencial_desde_certificado(certificado) for certificado in certificados),
        key=_prioridad_certificado_firma,
    )

    ultimo_error = None
    for credencial in candidatos:
        intentos = []
        if credencial.get("cert_id") is not None:
            intentos.append({"id": credencial["cert_id"]})
        if credencial.get("cert_label") is not None:
            intentos.append({"label": credencial["cert_label"]})

        for intento in intentos:
            try:
                session.get_key(ObjectClass.PRIVATE_KEY, **intento)
                if "id" in intento:
                    return {
                        "cert_id": credencial["cert_id"],
                        "key_id": credencial["cert_id"],
                        "datos_identidad": credencial["datos_identidad"],
                    }
                return {
                    "cert_label": credencial["cert_label"],
                    "key_label": credencial["cert_label"],
                    "datos_identidad": credencial["datos_identidad"],
                }
            except Exception as exc:
                ultimo_error = exc

    raise RuntimeError(
        "No se encontró una llave privada asociada al certificado de firma"
    ) from ultimo_error


def _credencial_desde_certificado(certificado):
    from pkcs11 import Attribute

    cert_id = _leer_atributo_pkcs11(certificado, Attribute.ID)
    cert_label = _leer_atributo_pkcs11(certificado, Attribute.LABEL)
    if isinstance(cert_label, bytes):
        cert_label = cert_label.decode("utf-8", errors="ignore")
    return {
        "cert_id": cert_id,
        "cert_label": cert_label,
        "datos_identidad": _extraer_datos_certificado(certificado),
    }


def _extraer_datos_certificado(certificado):
    from pkcs11 import Attribute

    certificado_der = _leer_atributo_pkcs11(certificado, Attribute.VALUE)
    if not certificado_der:
        return {"dni": None, "nombre_firmante": None, "subject": None}

    certificado_x509 = x509.Certificate.load(certificado_der)
    subject = certificado_x509.subject
    subject_native = subject.native or {}
    nombre_firmante = _primer_texto(subject_native.get("common_name"))
    subject_legible = subject.human_friendly

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
        "subject": subject_legible,
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
    if not dni_extraido and not datos_identidad.get("nombre_firmante"):
        raise RuntimeError("No se pudo extraer identidad del certificado del DNIe")


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


def _prioridad_certificado_firma(credencial):
    label = (credencial.get("cert_label") or "").lower()
    palabras_clave = ("firma", "sign", "signature", "non repudiation", "repudio")
    return 0 if any(palabra in label for palabra in palabras_clave) else 1


def _leer_atributo_pkcs11(objeto, atributo):
    try:
        return objeto[atributo]
    except Exception:
        return None


def _describir_error_firma(exc: Exception) -> str:
    mensaje = str(exc)
    mensaje_mayusculas = mensaje.upper()

    if MENSAJE_IDENTIDAD_FALLIDA.upper() in mensaje_mayusculas:
        return MENSAJE_IDENTIDAD_FALLIDA
    if "CKR_PIN_INCORRECT" in mensaje_mayusculas or "PIN_INCORRECT" in mensaje_mayusculas:
        return "PIN incorrecto"
    if "CKR_PIN_LOCKED" in mensaje_mayusculas or "PIN_LOCKED" in mensaje_mayusculas:
        return "PIN bloqueado. Revise el estado del DNIe"
    if "NO TOKEN FOUND" in mensaje_mayusculas or "TOKEN_NOT_PRESENT" in mensaje_mayusculas:
        return "DNIe no insertado o lector no detectado"
    if "OPENSC NO ESTÁ INSTALADO" in mensaje_mayusculas:
        return "OpenSC no está instalado"

    return mensaje or "No se pudo firmar el PDF"
