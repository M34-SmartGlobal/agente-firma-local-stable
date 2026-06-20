import re
from pathlib import Path

import PyKCS11
from asn1crypto import x509


OPENSC_PKCS11_RUTAS = [
    # Middlewares Oficiales DNIe Perú (Prioridad Alta)
    Path(r"C:\Program Files\IDEMIA\AWP\DLLs\OcsCryptoki.dll"),
    Path(r"C:\Program Files (x86)\IDEMIA\AWP\DLLs\OcsCryptoki.dll"),
    Path(r"C:\Program Files\Bit4Id\Universal MW\etc\bit4xpki.dll"),
    Path(r"C:\Program Files (x86)\Bit4Id\Universal MW\etc\bit4xpki.dll"),
    Path(r"C:\Windows\System32\bit4xpki.dll"),
    Path(r"C:\Windows\System32\Reniec_DNIe_PKCS11.dll"),
    Path(r"C:\Windows\System32\Reniec_DNIe_PKCS11_64.dll"),
    Path(r"C:\Windows\System32\eTPKCS11.dll"),
    # OpenSC Genérico (Fallback)
    Path(r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"),
    Path(r"C:\Program Files (x86)\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"),
]


def _registrar_log(log_callback, mensaje):
    if log_callback is not None:
        log_callback(mensaje)
    else:
        print(mensaje)


def detectar_dll_con_token(log_callback=None):
    global ULTIMO_ESCANEO_TOKEN_DETECTADO

    primera_dll_existente = None
    ULTIMO_ESCANEO_TOKEN_DETECTADO = False
    _registrar_log(log_callback, "\n--- INICIANDO ESCANEO DE DRIVERS PKCS#11 ---")

    for ruta in OPENSC_PKCS11_RUTAS:
        if not ruta.exists():
            continue

        if primera_dll_existente is None:
            primera_dll_existente = ruta

        try:
            _registrar_log(log_callback, f"Probando: {ruta.name}...")
            pkcs11 = PyKCS11.PyKCS11Lib()
            pkcs11.load(str(ruta))
            slots = pkcs11.getSlotList(tokenPresent=True)

            if len(slots) > 0:
                ULTIMO_ESCANEO_TOKEN_DETECTADO = True
                _registrar_log(
                    log_callback,
                    f"✅ ÉXITO: Tarjeta detectada en slot usando {ruta.name}",
                )
                return ruta
            else:
                _registrar_log(
                    log_callback,
                    f"⚠️ Cargado, pero no hay token en {ruta.name}",
                )
        except Exception as e:
            _registrar_log(log_callback, f"❌ Error con {ruta.name}: {str(e)}")
            continue

    _registrar_log(log_callback, "--- FIN DEL ESCANEO (SIN ÉXITO) ---\n")
    return primera_dll_existente


def refrescar_dll_con_token(log_callback=None):
    global OPENSC_PKCS11_DLL

    OPENSC_PKCS11_DLL = detectar_dll_con_token(log_callback=log_callback)
    return OPENSC_PKCS11_DLL


OPENSC_PKCS11_DLL = None
ULTIMO_ESCANEO_TOKEN_DETECTADO = False
PATRON_DNI = re.compile(r"(?<!\d)(\d{8})(?!\d)")


def verificar_dnie():
    try:
        if OPENSC_PKCS11_DLL is None:
            raise FileNotFoundError(
                "No se encontró ningún módulo PKCS#11 compatible"
            )

        pkcs11 = PyKCS11.PyKCS11Lib()
        pkcs11.load(str(OPENSC_PKCS11_DLL))

        slots = pkcs11.getSlotList(tokenPresent=True)

        if slots:
            return {"estado": "Conectado", "slots_encontrados": len(slots)}

        return {
            "estado": "Desconectado",
            "mensaje": "Inserte su DNIe en el lector",
        }
    except FileNotFoundError as exc:
        return {"estado": "Error", "mensaje": str(exc)}
    except PyKCS11.PyKCS11Error as exc:
        return {"estado": "Error", "mensaje": f"Error PKCS#11: {exc}"}
    except Exception as exc:
        return {"estado": "Error", "mensaje": f"Error al verificar DNIe: {exc}"}


def leer_certificado_dnie(recargar_driver=False, log_callback=None):
    if recargar_driver:
        refrescar_dll_con_token(log_callback=log_callback)

    if OPENSC_PKCS11_DLL is None:
        raise FileNotFoundError("No se encontró ningún módulo PKCS#11 compatible")

    pkcs11 = PyKCS11.PyKCS11Lib()
    pkcs11.load(str(OPENSC_PKCS11_DLL))

    slots = pkcs11.getSlotList(tokenPresent=True)
    if not slots:
        raise RuntimeError("No se detectó ninguna tarjeta DNIe insertada")

    ultimo_error = None
    for slot in slots:
        session = None
        try:
            session = pkcs11.openSession(slot)
            certificados = session.findObjects(
                [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
            )
            for certificado in certificados:
                try:
                    certificado_der = _leer_certificado_der(session, certificado)
                    if not certificado_der:
                        continue

                    datos = _extraer_identidad_certificado(certificado_der)
                    if datos.get("nombre") or datos.get("dni"):
                        return datos
                except Exception as exc:
                    ultimo_error = exc
        except Exception as exc:
            ultimo_error = exc
        finally:
            if session is not None:
                session.closeSession()

    raise RuntimeError("No se pudo leer el certificado del DNIe") from ultimo_error


def _leer_certificado_der(session, certificado):
    valor = session.getAttributeValue(
        certificado, [PyKCS11.CKA_VALUE], allAsBinary=True
    )[0]
    if isinstance(valor, bytes):
        return valor
    if isinstance(valor, bytearray):
        return bytes(valor)
    if isinstance(valor, (list, tuple)):
        return bytes(valor)
    return None


def _extraer_identidad_certificado(certificado_der):
    certificado_x509 = x509.Certificate.load(certificado_der)
    subject_native = certificado_x509.subject.native or {}

    nombre = _primer_texto(subject_native.get("common_name"))
    serial = _primer_texto(subject_native.get("serial_number"))
    dni = _extraer_dni(serial) or serial

    return {
        "status": "ok",
        "nombre": nombre or "",
        "dni": dni or "",
    }


def _extraer_dni(texto):
    if not texto:
        return None
    coincidencia = PATRON_DNI.search(str(texto))
    return coincidencia.group(1) if coincidencia else None


def _primer_texto(valor):
    if valor is None:
        return None
    if isinstance(valor, (list, tuple, set)):
        for item in valor:
            texto = _primer_texto(item)
            if texto:
                return texto
        return None
    if isinstance(valor, dict):
        for item in valor.values():
            texto = _primer_texto(item)
            if texto:
                return texto
        return None
    return str(valor)
