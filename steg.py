from flask import Flask, render_template, request, send_file
from PIL import Image
from cryptography.fernet import Fernet
import base64, hashlib, io

app = Flask(__name__)

# --- Key generator ---
def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# --- Hide message ---
def hide_message(image, message, password):
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode()).decode()

    img = Image.open(image)
    encoded = img.copy()
    width, height = img.size
    message = encrypted_message + "%%"
    binary_message = ''.join(format(ord(char), '08b') for char in message)

    data_index = 0
    for x in range(width):
        for y in range(height):
            if data_index < len(binary_message):
                pixel = list(img.getpixel((x, y)))
                for n in range(3):
                    if data_index < len(binary_message):
                        pixel[n] = pixel[n] & ~1 | int(binary_message[data_index])
                        data_index += 1
                encoded.putpixel((x, y), tuple(pixel))

    output = io.BytesIO()
    encoded.save(output, format="PNG")
    output.seek(0)
    return output

# --- Extract message ---
def extract_message(image, password):
    img = Image.open(image)
    binary_data = ""
    for x in range(img.size[0]):
        for y in range(img.size[1]):
            pixel = img.getpixel((x, y))
            for n in range(3):
                binary_data += str(pixel[n] & 1)

    message = ""
    for i in range(0, len(binary_data), 8):
        char = chr(int(binary_data[i:i+8], 2))
        message += char
        if message.endswith("%%"):
            encrypted_message = message[:-2]
            break

    try:
        key = generate_key(password)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message.encode()).decode()
    except:
        return None

@app.route("/", methods=["GET", "POST"])
def index():
    extracted_message = None
    error = None

    if request.method == "POST":
        action = request.form.get("action")
        password = request.form.get("password")

        if action == "hide":
            secret = request.form.get("secret")
            image = request.files["image"]
            stego_img = hide_message(image, secret, password)
            return send_file(stego_img, as_attachment=True, download_name="stego.png")

        elif action == "extract":
            image = request.files["image"]
            msg = extract_message(image, password)
            if msg:
                extracted_message = msg
            else:
                error = " Wrong passkey or corrupted image"

    return render_template("index.html", message=extracted_message, error=error)

if __name__ == "__main__":
    app.run(debug=True)
