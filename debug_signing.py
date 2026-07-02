#!/usr/bin/env python3
"""Diagnóstico: verificar que el signing vía PowerShell produce firmas correctas."""

import base64
import subprocess
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from asn1crypto import x509
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend

import ssl


def _make_ps_script(thumbprint, data_b64):
    """Genera script PowerShell que firma usando Get-Item."""
    return (
        '$cert = Get-Item -Path "Cert:\\CurrentUser\\My\\' + thumbprint + '"\n'
        "$rsa = [System.Security.Cryptography.RSACryptoServiceProvider]$cert.PrivateKey\n"
        '$raw = [System.Convert]::FromBase64String("' + data_b64 + '")\n'
        "$sig = $rsa.SignData($raw, [System.Security.Cryptography.HashAlgorithmName]::SHA256, "
        "[System.Security.Cryptography.RSASignaturePadding]::Pkcs1)\n"
        'Write-Output ("SIG:" + [System.Convert]::ToBase64String($sig))\n'
    )


def main():
    # 1. Leer certificado FIR
    cert_found = None
    for cert_bytes, encoding, trust in ssl.enum_certificates("MY"):
        if encoding != "x509_asn":
            continue
        cert = x509.Certificate.load(cert_bytes)
        issuer = cert.issuer.native
        if "RENIEC" in str(issuer).upper():
            nombre = str(cert.subject.native.get("common_name", "")).upper()
            if "FIR" in nombre:
                thumbprint = cert.sha1.hex().upper()
                cert_found = (thumbprint, cert_bytes)
                break

    if not cert_found:
        print("ERROR: No se encontró certificado FIR de RENIEC")
        return

    thumbprint, cert_bytes = cert_found
    print(f"Certificado encontrado:")
    print(f"  Thumbprint: {thumbprint}")

    # 2. Cargar con cryptography para verificación
    crypto_cert = load_der_x509_certificate(cert_bytes, default_backend())
    pub_key = crypto_cert.public_key()
    print(f"  Subject: {crypto_cert.subject}")
    print(f"  Algoritmo: {pub_key.key_size}-bit RSA")

    # 3. Crear datos de prueba
    test_data = b"Hello DNIe! Test data for signature verification."
    test_data_b64 = base64.b64encode(test_data).decode()

    # 4. Firmar vía PowerShell
    ps = _make_ps_script(thumbprint, test_data_b64)

    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )

    if result.returncode != 0:
        print(f"ERROR PowerShell: {result.stderr}")
        print(f"stdout: {result.stdout}")
        return

    sig_bytes = None
    for line in result.stdout.splitlines():
        if line.startswith("SIG:"):
            sig_bytes = base64.b64decode(line[4:])
            break

    if not sig_bytes:
        print("ERROR: No se encontró SIG: en la salida")
        print(f"stdout: {result.stdout}")
        return

    print(f"\nFirma generada:")
    print(f"  Tamaño: {len(sig_bytes)} bytes (debe ser 256)")
    print(f"  Hex (primeros 32): {sig_bytes[:32].hex()}")

    # 5. Verificar la firma
    try:
        pub_key.verify(
            sig_bytes,
            test_data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        print("\n✅ VERIFICACIÓN EXITOSA: La firma RSA es CORRECTA")
        print("   El problema está en cómo pyHanko construye el CMS")
    except Exception as e:
        print(f"\n❌ VERIFICACIÓN FALLÓ: {e}")
        print("   El problema está en el SIGNING (PowerShell/CAPI)")


if __name__ == "__main__":
    main()
