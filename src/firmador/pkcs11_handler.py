from pathlib import Path

import PyKCS11


OPENSC_PKCS11_DLL = Path(
    r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"
)


def verificar_dnie():
    try:
        if not OPENSC_PKCS11_DLL.exists():
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
