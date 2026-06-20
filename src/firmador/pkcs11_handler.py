from pathlib import Path

import PyKCS11


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


def detectar_opensc_pkcs11():
    for ruta in OPENSC_PKCS11_RUTAS:
        if ruta.exists():
            return ruta
    return None


OPENSC_PKCS11_DLL = detectar_opensc_pkcs11()


def verificar_dnie():
    try:
        if OPENSC_PKCS11_DLL is None:
            raise FileNotFoundError("OpenSC no está instalado")

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
