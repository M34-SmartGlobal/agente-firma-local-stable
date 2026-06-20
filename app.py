import multiprocessing
import os

from flask import Flask, jsonify, request
from flask_cors import CORS

from src.firmador import pkcs11_handler
from src.firmador.pdf_signer import firmar_pdf


ALLOWED_ORIGINS = [
    "https://nuevo-crm-rrhh.pages.dev",
    "http://localhost:3000"
]


# CRM_ORIGIN = "https://nuevo-crm-rrhh.pages.dev"
HOST = "127.0.0.1"
PORT = 5000
try:
    import customtkinter
except ModuleNotFoundError:
    customtkinter = None


flask_app = Flask(__name__)
CORS(
    flask_app,
    resources={r"/*": {"origins": ALLOWED_ORIGINS}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


@flask_app.get("/status")
def status():
    return jsonify(
        {
            "status": "online",
            "message": "Agente de firma local escuchando",
        }
    )


@flask_app.get("/api/dnie/status")
def dnie_status():
    return jsonify(pkcs11_handler.verificar_dnie())


@flask_app.get("/api/dnie/leer-certificado")
def dnie_leer_certificado():
    try:
        return jsonify(pkcs11_handler.leer_certificado_dnie())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@flask_app.post("/api/dnie/firmar")
def dnie_firmar():
    data = request.get_json(silent=True) or {}
    pdf_base64 = data.get("pdf_base64")
    pin = data.get("pin")
    dni_esperado = data.get("dni_esperado")

    try:
        resultado = firmar_pdf(pdf_base64, pin, dni_esperado)
        return jsonify({"status": "success", **resultado})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


def iniciar_servidor_flask():
    flask_app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


class App(customtkinter.CTk if customtkinter else object):
    def __init__(self, servidor=None):
        if customtkinter is None:
            raise RuntimeError(
                "No se pudo iniciar la interfaz gráfica. Instale Tkinter en este "
                "Python y luego ejecute pip install -r requirements.txt."
            )

        super().__init__()

        self.title("Motor Criptográfico - MASGLOBAL")
        self.geometry("450x390")
        self.resizable(False, False)
        self.servidor = servidor

        self._configurar_layout()

    def _configurar_layout(self):
        self.grid_columnconfigure(0, weight=1)

        self.contenedor = customtkinter.CTkFrame(self, corner_radius=18)
        self.contenedor.grid(row=0, column=0, padx=24, pady=24, sticky="nsew")
        self.contenedor.grid_columnconfigure(0, weight=1)

        self.titulo = customtkinter.CTkLabel(
            self.contenedor,
            text="Agente de Firma Local",
            font=customtkinter.CTkFont(size=24, weight="bold"),
        )
        self.titulo.grid(row=0, column=0, padx=24, pady=(28, 8))

        self.subtitulo = customtkinter.CTkLabel(
            self.contenedor,
            text="Puente seguro entre CRM y DNIe",
            font=customtkinter.CTkFont(size=13),
            text_color="#9ca3af",
        )
        self.subtitulo.grid(row=1, column=0, padx=24, pady=(0, 22))

        self.separador = customtkinter.CTkFrame(
            self.contenedor, height=1, fg_color="#374151"
        )
        self.separador.grid(row=2, column=0, padx=32, pady=(0, 22), sticky="ew")

        self.label_servidor = customtkinter.CTkLabel(
            self.contenedor,
            text=f"Servidor: 🟢 Online (Puerto {PORT})",
            font=customtkinter.CTkFont(size=15, weight="bold"),
            text_color="#22c55e",
        )
        self.label_servidor.grid(row=3, column=0, padx=24, pady=(0, 14))

        self.label_motor = customtkinter.CTkLabel(
            self.contenedor,
            text="Motor: Windows CAPI (Nativo) Listo",
            font=customtkinter.CTkFont(size=15, weight="bold"),
            text_color="#22c55e",
        )
        self.label_motor.grid(row=4, column=0, padx=24, pady=(0, 28))

        self.boton_cerrar = customtkinter.CTkButton(
            self.contenedor,
            text="Cerrar Sistema",
            command=self.cerrar_sistema,
            fg_color="#991b1b",
            hover_color="#7f1d1d",
            height=42,
            corner_radius=12,
            font=customtkinter.CTkFont(size=14, weight="bold"),
        )
        self.boton_cerrar.grid(row=5, column=0, padx=64, pady=(0, 18), sticky="ew")

        self.aviso_corporativo = customtkinter.CTkLabel(
            self.contenedor,
            text="Uso corporativo estrictamente privado. Propiedad exclusiva de MASGLOBAL.",
            font=customtkinter.CTkFont(size=10),
            text_color="#6b7280",
            wraplength=360,
        )
        self.aviso_corporativo.grid(row=6, column=0, padx=24, pady=(0, 22))

    def cerrar_sistema(self):
        if self.servidor is not None and self.servidor.is_alive():
            self.servidor.terminate()
            self.servidor.join(timeout=2)
        self.destroy()
        os._exit(0)


if __name__ == "__main__":
    if customtkinter is None:
        raise SystemExit(
            "No se pudo iniciar la interfaz gráfica: Tkinter no está disponible."
        )

    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("blue")

    multiprocessing.freeze_support()
    servidor = multiprocessing.Process(target=iniciar_servidor_flask, daemon=True)
    servidor.start()

    app = App(servidor=servidor)
    app.mainloop()
