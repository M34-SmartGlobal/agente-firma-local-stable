import os
import threading

from flask import Flask, jsonify, request
from flask_cors import CORS

from src.firmador.pkcs11_handler import verificar_dnie
from src.firmador.pdf_simulator import simular_firma_pdf
from src.firmador.pdf_signer import firmar_pdf


ALLOWED_ORIGINS = [
    "https://nuevo-crm-rrhh.pages.dev",
    "http://localhost:3000"
]


# CRM_ORIGIN = "https://nuevo-crm-rrhh.pages.dev"
HOST = "127.0.0.1"
PORT = 5000
MODO_SIMULADOR = True

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
    if MODO_SIMULADOR:
        return jsonify(
            {
                "estado": "Conectado",
                "mensaje": "Modo simulador activo. No se requiere lector físico.",
                "modo_simulador": True,
            }
        )
    return jsonify(verificar_dnie())


@flask_app.post("/api/dnie/firmar")
def dnie_firmar():
    data = request.get_json(silent=True) or {}
    pdf_base64 = data.get("pdf_base64")
    pin = data.get("pin")
    dni_esperado = data.get("dni_esperado")

    try:
        if MODO_SIMULADOR:
            resultado = simular_firma_pdf(pdf_base64)
        else:
            resultado = firmar_pdf(pdf_base64, pin, dni_esperado)
        return jsonify({"status": "success", **resultado})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


def iniciar_servidor_flask():
    flask_app.run(host=HOST, port=PORT, debug=False, use_reloader=False)


class App(customtkinter.CTk if customtkinter else object):
    def __init__(self):
        if customtkinter is None:
            raise RuntimeError(
                "No se pudo iniciar la interfaz gráfica. Instale Tkinter en este "
                "Python y luego ejecute pip install -r requirements.txt."
            )

        super().__init__()

        self.title("Motor Criptográfico - MASGLOBAL")
        self.geometry("450x430")
        self.resizable(False, False)
        self._consulta_lector_en_progreso = False

        self._configurar_layout()
        self.actualizar_estado_lector()

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

        self.switch_simulador = customtkinter.CTkSwitch(
            self.contenedor,
            text="Modo Simulador (Sin Lector)",
            command=self.actualizar_modo_simulador,
            font=customtkinter.CTkFont(size=13, weight="bold"),
        )
        self.switch_simulador.grid(row=4, column=0, padx=24, pady=(0, 16))
        if MODO_SIMULADOR:
            self.switch_simulador.select()

        self.label_lector = customtkinter.CTkLabel(
            self.contenedor,
            text="Lector USB: Buscando...",
            font=customtkinter.CTkFont(size=15, weight="bold"),
            text_color="#f59e0b",
        )
        self.label_lector.grid(row=5, column=0, padx=24, pady=(0, 28))

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
        self.boton_cerrar.grid(row=6, column=0, padx=64, pady=(0, 18), sticky="ew")

        self.aviso_corporativo = customtkinter.CTkLabel(
            self.contenedor,
            text="Uso corporativo estrictamente privado. Propiedad exclusiva de MASGLOBAL.",
            font=customtkinter.CTkFont(size=10),
            text_color="#6b7280",
            wraplength=360,
        )
        self.aviso_corporativo.grid(row=7, column=0, padx=24, pady=(0, 22))

    def actualizar_modo_simulador(self):
        global MODO_SIMULADOR

        MODO_SIMULADOR = bool(self.switch_simulador.get())
        if MODO_SIMULADOR:
            self._actualizar_label_lector(
                "Lector USB: 🔵 Simulador activo (sin lector)", "#38bdf8"
            )

    def actualizar_estado_lector(self):
        if MODO_SIMULADOR:
            self._actualizar_label_lector(
                "Lector USB: 🔵 Simulador activo (sin lector)", "#38bdf8"
            )
            self.after(3000, self.actualizar_estado_lector)
            return

        if not self._consulta_lector_en_progreso:
            self._consulta_lector_en_progreso = True
            threading.Thread(target=self._consultar_estado_lector, daemon=True).start()

        self.after(3000, self.actualizar_estado_lector)

    def _consultar_estado_lector(self):
        try:
            resultado = verificar_dnie()
            estado = resultado.get("estado", "Error")

            if estado == "Conectado":
                texto = f"Lector USB: 🟢 DNIe conectado ({resultado.get('slots_encontrados', 0)} slot)"
                color = "#22c55e"
            elif estado == "Desconectado":
                texto = "Lector USB: 🟡 DNIe no insertado"
                color = "#f59e0b"
            else:
                texto = f"Lector USB: 🔴 {resultado.get('mensaje', 'Error de hardware')}"
                color = "#ef4444"

            self.after(0, self._actualizar_label_lector, texto, color)
        finally:
            self._consulta_lector_en_progreso = False

    def _actualizar_label_lector(self, texto, color):
        self.label_lector.configure(text=texto, text_color=color)

    def cerrar_sistema(self):
        self.destroy()
        os._exit(0)


if __name__ == "__main__":
    if customtkinter is None:
        raise SystemExit(
            "No se pudo iniciar la interfaz gráfica: Tkinter no está disponible."
        )

    customtkinter.set_appearance_mode("dark")
    customtkinter.set_default_color_theme("blue")

    servidor = threading.Thread(target=iniciar_servidor_flask, daemon=True)
    servidor.start()

    app = App()
    app.mainloop()
