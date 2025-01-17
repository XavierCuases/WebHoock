from flask import Flask, request, jsonify
import hmac
import hashlib

app = Flask(__name__)

# Clave secreta para validar la autenticidad del remitente
SECRET_KEY = "mysecretkey"

# Función para validar la firma HMAC
def validate_signature(payload, signature):
    """
    Valida la firma HMAC del webhook.
    """
    computed_signature = hmac.new(
        SECRET_KEY.encode('utf-8'), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed_signature, signature)

# Ruta principal para verificar que el servidor está funcionando
@app.route('/', methods=['GET'])
def home():
    return "El servidor Flask está funcionando correctamente", 200

# Ruta para el webhook (POST)
@app.route('/webhook', methods=['POST'])
def webhook():
    # Validar el cuerpo de la solicitud
    payload = request.data
    if not payload:
        return jsonify({"error": "Cuerpo vacío"}), 400

    # Leer la firma del encabezado
    signature = request.headers.get('X-Signature')
    if not signature:
        return jsonify({"error": "Firma no proporcionada"}), 403

    # Validar la firma
    if not validate_signature(payload, signature):
        return jsonify({"error": "Firma inválida"}), 403

    # Procesar el evento
    try:
        data = request.get_json()
        event = data.get("event")
        message = data.get("message")
        user_id = data.get("user_id")

        # Registrar el evento recibido
        app.logger.info(f"Evento recibido: {event}, Mensaje: {message}, Usuario: {user_id}")

        return jsonify({"message": "Evento procesado correctamente"}), 200
    except Exception as e:
        app.logger.error(f"Error al procesar el evento: {e}")
        return jsonify({"error": "Error procesando el evento"}), 500

# Iniciar el servidor Flask en el puerto 4000
if __name__ == "__main__":
    app.run(port=4000, debug=True)
