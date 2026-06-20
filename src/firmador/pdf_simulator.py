import base64
import binascii
from datetime import datetime
from io import BytesIO


SELLO_SIMULADO = "FIRMADO DIGITALMENTE (SIMULACIÓN) - JEAR CHRISTIAN CAMPOVERDE CUNYA"


def simular_firma_pdf(pdf_base64: str) -> dict:
    if not pdf_base64:
        raise ValueError("Debe enviar el PDF en Base64")

    pdf_bytes = _decodificar_pdf(pdf_base64)

    try:
        from PyPDF2 import PdfReader, PdfWriter
        from reportlab.lib.colors import HexColor
        from reportlab.pdfgen import canvas
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Faltan dependencias para el modo simulador. Ejecute pip install -r requirements.txt"
        ) from exc

    reader = PdfReader(BytesIO(pdf_bytes))
    if not reader.pages:
        raise ValueError("El PDF no contiene páginas")

    writer = PdfWriter()
    ultima_pagina_index = len(reader.pages) - 1

    for index, page in enumerate(reader.pages):
        if index == ultima_pagina_index:
            width = float(page.mediabox.width)
            height = float(page.mediabox.height)
            overlay = _crear_sello_overlay(canvas, HexColor, width, height)
            page.merge_page(PdfReader(overlay).pages[0])
        writer.add_page(page)

    output = BytesIO()
    writer.write(output)

    return {
        "pdf_firmado": base64.b64encode(output.getvalue()).decode("ascii"),
        "dni_extraido": None,
        "nombre_firmante": "JEAR CHRISTIAN CAMPOVERDE CUNYA",
        "modo_simulador": True,
    }


def _crear_sello_overlay(canvas_module, color_factory, width: float, height: float):
    packet = BytesIO()
    c = canvas_module.Canvas(packet, pagesize=(width, height))

    sello_ancho = min(500, width - 72)
    sello_alto = 68
    x = 36
    y = 36

    c.setStrokeColor(color_factory("#2563eb"))
    c.setFillColor(color_factory("#eff6ff"))
    c.roundRect(x, y, sello_ancho, sello_alto, 8, stroke=1, fill=1)

    c.setFillColor(color_factory("#1e3a8a"))
    c.setFont("Helvetica-Bold", 9)
    c.drawString(x + 16, y + 42, SELLO_SIMULADO)

    fecha = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.setFillColor(color_factory("#475569"))
    c.setFont("Helvetica", 8)
    c.drawString(x + 16, y + 22, f"Fecha de simulación: {fecha}")

    c.save()
    packet.seek(0)
    return packet


def _decodificar_pdf(pdf_base64: str) -> bytes:
    contenido = pdf_base64.split(",", 1)[1] if "," in pdf_base64 else pdf_base64
    try:
        pdf_bytes = base64.b64decode(contenido, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("El PDF recibido no es Base64 válido") from exc

    if not pdf_bytes.startswith(b"%PDF"):
        raise ValueError("El archivo recibido no parece ser un PDF válido")
    return pdf_bytes
