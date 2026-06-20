import ssl

from asn1crypto import x509


def verificar_dnie():
    return {
        "estado": "Conectado",
        "mensaje": "Motor Windows CAPI disponible",
        "motor": "Windows CAPI",
    }


def leer_certificado_dnie():
    try:
        certificados = ssl.enum_certificates("MY")
    except Exception as e:
        raise RuntimeError(f"Error al acceder a Windows CAPI: {str(e)}")

    for cert_bytes, encoding, trust in certificados:
        if encoding == "x509_asn":
            cert = x509.Certificate.load(cert_bytes)
            issuer = cert.issuer.native

            if "RENIEC" in str(issuer).upper():
                subject = cert.subject.native
                return {
                    "nombre": subject.get("common_name"),
                    "dni": subject.get("serial_number"),
                }

    raise RuntimeError(
        "No se detectó el certificado de la RENIEC en el almacén de Windows. "
        "Inserte el DNIe."
    )
