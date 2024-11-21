import sys
import os
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QLineEdit, QLabel,
    QFileDialog, QVBoxLayout, QWidget, QRadioButton, QButtonGroup, QTextEdit, QMessageBox, QComboBox
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding, hashes


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def atbash_cipher(text: str) -> str:
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    russian_alphabet = 'абвгдеёжзийклмнопрстуфхцчшщыэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЫЭЮЯ'
    full_alphabet = alphabet + russian_alphabet
    reversed_alphabet = full_alphabet[::-1]
    trans = str.maketrans(full_alphabet, reversed_alphabet)
    return text.translate(trans)


def ascii_shift_cipher(data, shift=3):
    def shift_char(char, shift):
        if 'a' <= char <= 'z':
            return chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            return chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
        elif 'а' <= char <= 'я':
            return chr((ord(char) - ord('а') + shift) % 32 + ord('а'))
        elif 'А' <= char <= 'Я':
            return chr((ord(char) - ord('А') + shift) % 32 + ord('А'))
        elif '0' <= char <= '9':
            return chr((ord(char) - ord('0') + shift) % 10 + ord('0'))
        else:
            return char

    if isinstance(data, str):
        return ''.join(shift_char(char, shift) for char in data)
    elif isinstance(data, bytes):
        return ''.join(shift_char(chr(byte), shift) for byte in data).encode('utf-8')
    else:
        raise TypeError("Unsupported data type for ASCII shift cipher.")


class EncryptDecryptApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Encryptor/Decryptor")
        self.setGeometry(300, 300, 600, 400)
        self.layout = QVBoxLayout()

        self.password_option_group = QButtonGroup()
        self.with_password_radio = QRadioButton("С паролем")
        self.without_password_radio = QRadioButton("Без пароля")
        self.password_option_group.addButton(self.with_password_radio)
        self.password_option_group.addButton(self.without_password_radio)
        self.layout.addWidget(self.with_password_radio)
        self.layout.addWidget(self.without_password_radio)
        self.with_password_radio.setChecked(True)

        self.password_label = QLabel("Введите пароль:")
        self.layout.addWidget(self.password_label)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.layout.addWidget(self.password_input)

        self.algorithm_label = QLabel("Выберите алгоритм:")
        self.layout.addWidget(self.algorithm_label)
        self.algorithm_dropdown = QComboBox()
        self.algorithm_dropdown.addItems(["AES", "Triple DES", "Atbash Cipher", "ASCII Shift"])
        self.layout.addWidget(self.algorithm_dropdown)

        self.file_label = QLabel("Выберите файл:")
        self.layout.addWidget(self.file_label)
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.layout.addWidget(self.file_path)
        self.select_file_button = QPushButton("Выбрать файл")
        self.select_file_button.clicked.connect(self.select_file)
        self.layout.addWidget(self.select_file_button)

        self.text_input = QTextEdit()
        self.layout.addWidget(self.text_input)

        self.encrypt_button = QPushButton("Зашифровать")
        self.encrypt_button.clicked.connect(self.encrypt)
        self.layout.addWidget(self.encrypt_button)
        self.decrypt_button = QPushButton("Расшифровать")
        self.decrypt_button.clicked.connect(self.decrypt)
        self.layout.addWidget(self.decrypt_button)

        central_widget = QWidget()
        central_widget.setLayout(self.layout)
        self.setCentralWidget(central_widget)

        self.with_password_radio.toggled.connect(self.update_ui)
        self.update_ui()

    def update_ui(self):
        if self.with_password_radio.isChecked():
            self.password_label.show()
            self.password_input.show()
            self.algorithm_dropdown.clear()
            self.algorithm_dropdown.addItems(["AES", "Triple DES"])
        else:
            self.password_label.hide()
            self.password_input.hide()
            self.algorithm_dropdown.clear()
            self.algorithm_dropdown.addItems(["Atbash Cipher", "ASCII Shift"])

    def select_file(self):
        file_dialog = QFileDialog()
        file_path, _ = file_dialog.getOpenFileName(self, "Выберите файл")
        if file_path:
            self.file_path.setText(file_path)

    def encrypt(self):
        file_path = self.file_path.text()
        text = self.text_input.toPlainText()
        password = self.password_input.text()
        algorithm = self.algorithm_dropdown.currentText()

        if self.with_password_radio.isChecked():
            if not password:
                QMessageBox.warning(self, "Ошибка", "Введите пароль.")
                return

            if file_path:
                output_path = file_path.rsplit(".", 1)[0] + "_enc." + file_path.rsplit(".", 1)[1]
                try:
                    encrypt_file(file_path, password, output_path, algorithm)
                    QMessageBox.information(self, "Успех", f"Файл зашифрован и сохранен как {output_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать файл: {e}")
            elif text:
                encrypted_text = encrypt_text_with_password(text, password, algorithm)
                self.text_input.setText(encrypted_text)
                QMessageBox.information(self, "Успех", "Текст зашифрован.")
        else:
            if file_path:
                output_path = file_path.rsplit(".", 1)[0] + "_enc." + file_path.rsplit(".", 1)[1]
                try:
                    encrypt_file_without_password(file_path, output_path, algorithm)
                    QMessageBox.information(self, "Успех", f"Файл зашифрован и сохранен как {output_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось зашифровать файл: {e}")
            elif text:
                encrypted_text = encrypt_text_without_password(text, algorithm)
                self.text_input.setText(encrypted_text)
                QMessageBox.information(self, "Успех", "Текст зашифрован.")

        self.password_input.clear()
        self.file_path.clear()

    def decrypt(self):
        file_path = self.file_path.text()
        text = self.text_input.toPlainText()
        password = self.password_input.text()
        algorithm = self.algorithm_dropdown.currentText()

        if self.with_password_radio.isChecked():
            if not password:
                QMessageBox.warning(self, "Ошибка", "Введите пароль.")
                return

            if file_path:
                output_path = file_path.rsplit(".", 1)[0] + "_dec." + file_path.rsplit(".", 1)[1]
                try:
                    decrypt_file(file_path, password, output_path, algorithm)
                    QMessageBox.information(self, "Успех", f"Файл расшифрован и сохранен как {output_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать файл: {e}")
            elif text:
                decrypted_text = decrypt_text_with_password(text, password, algorithm)
                self.text_input.setText(decrypted_text)
                QMessageBox.information(self, "Успех", "Текст расшифрован.")
        else:
            if file_path:
                output_path = file_path.rsplit(".", 1)[0] + "_dec." + file_path.rsplit(".", 1)[1]
                try:
                    decrypt_file_without_password(file_path, output_path, algorithm)
                    QMessageBox.information(self, "Успех", f"Файл расшифрован и сохранен как {output_path}")
                except Exception as e:
                    QMessageBox.critical(self, "Ошибка", f"Не удалось расшифровать файл: {e}")
            elif text:
                decrypted_text = decrypt_text_without_password(text, algorithm)
                self.text_input.setText(decrypted_text)
                QMessageBox.information(self, "Успех", "Текст расшифрован.")

        self.password_input.clear()
        self.file_path.clear()


def encrypt_text_with_password(text: str, password: str, algorithm: str) -> str:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    encrypted_text = (salt + iv + encrypted_data).hex()
    return encrypted_text


def decrypt_text_with_password(encrypted_text: str, password: str, algorithm: str) -> str:
    encrypted_data = bytes.fromhex(encrypted_text)
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    data = encrypted_data[32:]

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(padded_data) + unpadder.finalize()

    return decrypted_data.decode()


def encrypt_text_without_password(text: str, algorithm: str) -> str:
    if algorithm == "Atbash Cipher":
        return atbash_cipher(text)
    elif algorithm == "ASCII Shift":
        return ascii_shift_cipher(text)
    else:
        raise ValueError("Unknown algorithm")


def decrypt_text_without_password(encrypted_text: str, algorithm: str) -> str:
    if algorithm == "Atbash Cipher":
        return atbash_cipher(encrypted_text)
    elif algorithm == "ASCII Shift":
        return ascii_shift_cipher(encrypted_text, -3)
    else:
        raise ValueError("Unknown algorithm")


def encrypt_file(file_path: str, password: str, output_path: str, algorithm: str) -> None:
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    with open(output_path, 'wb') as f:
        f.write(salt + iv + encrypted_data)


def decrypt_file(file_path: str, password: str, output_path: str, algorithm: str) -> None:
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_path, 'wb') as f:
        f.write(data)


def atbash_cipher_bytes(data: bytes) -> bytes:
    full_byte_range = bytes(range(256))
    reversed_byte_range = full_byte_range[::-1]
    translation_table = bytes.maketrans(full_byte_range, reversed_byte_range)
    return data.translate(translation_table)


def encrypt_file_without_password(file_path: str, output_path: str, algorithm: str):
    with open(file_path, "rb") as f:
        file_data = f.read()
    if algorithm == "Atbash Cipher":
        encrypted_data = atbash_cipher_bytes(file_data)
    elif algorithm == "ASCII Shift":
        try:
            text = file_data.decode('utf-8')
            encrypted_data = ascii_shift_cipher(text).encode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Файл содержит не текстовые данные, и его нельзя обработать ASCII Shift.")
    else:
        raise ValueError("Unknown algorithm")

    with open(output_path, "wb") as f:
        f.write(encrypted_data)


def decrypt_file_without_password(file_path: str, output_path: str, algorithm: str):
    with open(file_path, "rb") as f:
        encrypted_data = f.read()
    if algorithm == "Atbash Cipher":
        decrypted_data = atbash_cipher_bytes(encrypted_data)
    elif algorithm == "ASCII Shift":
        try:
            text = encrypted_data.decode('utf-8')
            decrypted_data = ascii_shift_cipher(text, -3).encode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Файл содержит не текстовые данные, и его нельзя обработать ASCII Shift.")
    else:
        raise ValueError("Unknown algorithm")
    with open(output_path, "wb") as f:
        f.write(decrypted_data)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EncryptDecryptApp()
    window.show()
    sys.exit(app.exec())