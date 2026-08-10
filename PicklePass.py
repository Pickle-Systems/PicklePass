from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import pyotp
from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QStackedWidget,
    QStatusBar,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# ============================================================
# APPLICATION
# ============================================================

APP_NAME = "PicklePass"

APP_DIR = Path.home() / "AppData" / "Local" / "PicklePass"
VAULT_FILE = APP_DIR / "PicklePass.vault"
BACKUP_DIR = APP_DIR / "backups"

APP_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# VAULT FORMAT
# ============================================================

MAGIC = b"PPVAULT"
VERSION = 1

PAYLOAD_AAD = b"PicklePass-Vault-Payload-v1"
WRAPPED_KEY_AAD = b"PicklePass-Vault-Key-v1"

ARGON_TIME = 3
ARGON_MEMORY = 256 * 1024
ARGON_PARALLELISM = 4
ARGON_HASH_LENGTH = 32


# ============================================================
# SECURITY HELPERS
# ============================================================

def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data.encode("ascii"))


def derive_password_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON_TIME,
        memory_cost=ARGON_MEMORY,
        parallelism=ARGON_PARALLELISM,
        hash_len=ARGON_HASH_LENGTH,
        type=Argon2Type.ID,
    )


def derive_subkey(key: bytes, purpose: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"PicklePass/" + purpose,
    ).derive(key)


def aes_encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = random_bytes(12)

    ciphertext = AESGCM(key).encrypt(
        nonce,
        plaintext,
        aad,
    )

    return nonce + ciphertext


def aes_decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < 28:
        raise ValueError("Encrypted data is too short.")

    nonce = blob[:12]
    ciphertext = blob[12:]

    return AESGCM(key).decrypt(
        nonce,
        ciphertext,
        aad,
    )


# ============================================================
# FILE HELPERS
# ============================================================

def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, temporary_name = tempfile.mkstemp(
        prefix=".picklepass-",
        suffix=".tmp",
        dir=str(path.parent),
    )

    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_name, path)

    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def create_backup() -> None:
    if not VAULT_FILE.exists():
        return

    timestamp = time.strftime("%Y%m%d-%H%M%S")

    destination = (
        BACKUP_DIR
        / f"PicklePass-{timestamp}-{secrets.token_hex(3)}.vault.bak"
    )

    shutil.copy2(VAULT_FILE, destination)


# ============================================================
# VAULT
# ============================================================

class VaultError(Exception):
    pass


class Vault:
    def __init__(self) -> None:
        self.data_key: bytes | None = None

        self.data: dict[str, Any] = {
            "entries": [],
            "settings": {
                "auto_lock_minutes": 15,
            },
        }

    @property
    def exists(self) -> bool:
        return VAULT_FILE.exists()

    @property
    def unlocked(self) -> bool:
        return self.data_key is not None

    def create(self, password: str) -> None:
        if len(password) < 1:
            raise VaultError(
                "Master password cannot be empty."
            )

        self.data_key = random_bytes(32)

        salt = random_bytes(16)

        password_key = derive_password_key(
            password,
            salt,
        )

        wrapping_key = derive_subkey(
            password_key,
            b"vault-key",
        )

        wrapped_data_key = aes_encrypt(
            wrapping_key,
            self.data_key,
            WRAPPED_KEY_AAD,
        )

        header = {
            "version": VERSION,
            "kdf": "argon2id",
            "cipher": "aes-256-gcm",
            "salt": b64e(salt),
            "wrapped_data_key": b64e(wrapped_data_key),
        }

        self._write(
            header,
            create_backup=False,
        )

    def unlock(self, password: str) -> None:
        if not VAULT_FILE.exists():
            raise VaultError("Vault does not exist.")

        try:
            raw = VAULT_FILE.read_bytes()

            minimum_size = len(MAGIC) + 1 + 4

            if len(raw) < minimum_size:
                raise VaultError("Vault is damaged.")

            if not raw.startswith(MAGIC):
                raise VaultError("Invalid PicklePass vault.")

            offset = len(MAGIC)

            version = raw[offset]
            offset += 1

            if version != VERSION:
                raise VaultError(
                    "Unsupported PicklePass vault version."
                )

            header_length = int.from_bytes(
                raw[offset:offset + 4],
                "big",
            )

            offset += 4

            header_end = offset + header_length

            if header_end > len(raw):
                raise VaultError("Vault header is damaged.")

            header = json.loads(
                raw[offset:header_end].decode("utf-8")
            )

            encrypted_payload = raw[header_end:]

            salt = b64d(header["salt"])

            password_key = derive_password_key(
                password,
                salt,
            )

            wrapping_key = derive_subkey(
                password_key,
                b"vault-key",
            )

            wrapped_data_key = b64d(
                header["wrapped_data_key"]
            )

            data_key = aes_decrypt(
                wrapping_key,
                wrapped_data_key,
                WRAPPED_KEY_AAD,
            )

            if len(data_key) != 32:
                raise VaultError(
                    "Invalid vault encryption key."
                )

            payload_key = derive_subkey(
                data_key,
                b"vault-data",
            )

            plaintext = aes_decrypt(
                payload_key,
                encrypted_payload,
                PAYLOAD_AAD,
            )

            decoded = json.loads(
                plaintext.decode("utf-8")
            )

            if not isinstance(decoded, dict):
                raise VaultError(
                    "Invalid vault contents."
                )

            entries = decoded.get("entries", [])

            if not isinstance(entries, list):
                raise VaultError(
                    "Invalid vault entries."
                )

            settings = decoded.get("settings", {})

            if not isinstance(settings, dict):
                settings = {}

            self.data = decoded
            self.data["entries"] = entries
            self.data["settings"] = settings
            self.data_key = data_key

        except VaultError:
            raise

        except Exception as exc:
            raise VaultError(
                "Incorrect master password or damaged vault."
            ) from exc

    def lock(self) -> None:
        self.data_key = None

        self.data = {
            "entries": [],
            "settings": {
                "auto_lock_minutes": 15,
            },
        }

    def _write(
        self,
        header: dict[str, Any],
        create_backup_before_write: bool = True,
    ) -> None:
        if self.data_key is None:
            raise VaultError("Vault is locked.")

        plaintext = json.dumps(
            self.data,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")

        payload_key = derive_subkey(
            self.data_key,
            b"vault-data",
        )

        encrypted_payload = aes_encrypt(
            payload_key,
            plaintext,
            PAYLOAD_AAD,
        )

        header_bytes = json.dumps(
            header,
            separators=(",", ":"),
        ).encode("utf-8")

        output = (
            MAGIC
            + bytes([VERSION])
            + len(header_bytes).to_bytes(4, "big")
            + header_bytes
            + encrypted_payload
        )

        if create_backup_before_write:
            create_backup()

        atomic_write(
            VAULT_FILE,
            output,
        )

    def save(self) -> None:
        if self.data_key is None:
            raise VaultError("Vault is locked.")

        raw = VAULT_FILE.read_bytes()

        offset = len(MAGIC) + 1

        header_length = int.from_bytes(
            raw[offset:offset + 4],
            "big",
        )

        offset += 4

        header = json.loads(
            raw[offset:offset + header_length].decode(
                "utf-8"
            )
        )

        self._write(
            header,
            create_backup_before_write=True,
        )

    def entries(self) -> list[dict[str, Any]]:
        entries = self.data.setdefault(
            "entries",
            [],
        )

        if not isinstance(entries, list):
            entries = []
            self.data["entries"] = entries

        return entries

    def add_entry(self, entry: dict[str, Any]) -> None:
        now = int(time.time())

        item = dict(entry)
        item["id"] = secrets.token_hex(16)
        item["created"] = now
        item["updated"] = now

        self.entries().append(item)
        self.save()

    def update_entry(
        self,
        entry_id: str,
        entry: dict[str, Any],
    ) -> None:
        for index, old in enumerate(self.entries()):
            if old.get("id") != entry_id:
                continue

            updated = dict(entry)

            updated["id"] = entry_id
            updated["created"] = old.get(
                "created",
                int(time.time()),
            )
            updated["updated"] = int(time.time())

            self.entries()[index] = updated

            self.save()
            return

        raise VaultError("Entry not found.")

    def delete_entry(self, entry_id: str) -> None:
        self.data["entries"] = [
            item
            for item in self.entries()
            if item.get("id") != entry_id
        ]

        self.save()


# ============================================================
# PASSWORD GENERATOR
# ============================================================

def generate_password(length: int = 28) -> str:
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "!@#$%^&*()-_=+[]{}:,.?"
    )

    return "".join(
        secrets.choice(alphabet)
        for _ in range(length)
    )


# ============================================================
# UI HELPERS
# ============================================================

STYLE = """
QWidget {
    background: #080d15;
    color: #e8f0f7;
    font-family: "Segoe UI";
    font-size: 14px;
}

QMainWindow {
    background: #080d15;
}

QFrame#Sidebar {
    background: #0b111b;
    border-right: 1px solid #1c2a3a;
}

QFrame#Card {
    background: #0d1520;
    border: 1px solid #1b2a3b;
    border-radius: 14px;
}

QFrame#StatCard {
    background: #0c1420;
    border: 1px solid #1c2c3e;
    border-radius: 12px;
}

QLabel#Logo {
    font-size: 24px;
    font-weight: 700;
    color: #f3f8fc;
}

QLabel#LogoAccent {
    color: #27c7ff;
}

QLabel#PageTitle {
    font-size: 27px;
    font-weight: 700;
    color: #f3f8fc;
}

QLabel#PageSubtitle {
    color: #73869a;
    font-size: 13px;
}

QLabel#SectionTitle {
    font-size: 12px;
    font-weight: 700;
    color: #64798d;
}

QLabel#StatNumber {
    font-size: 24px;
    font-weight: 700;
    color: #f2f7fb;
}

QLabel#StatCaption {
    color: #71859a;
    font-size: 12px;
}

QLabel#Cyan {
    color: #27c7ff;
}

QLabel#Green {
    color: #36df9a;
}

QLabel#Warning {
    color: #ffbf5b;
}

QLineEdit,
QTextEdit {
    background: #0a111a;
    color: #edf5fa;
    border: 1px solid #243548;
    border-radius: 8px;
    padding: 9px;
    selection-background-color: #176e92;
}

QLineEdit:focus,
QTextEdit:focus {
    border: 1px solid #27c7ff;
}

QPushButton {
    background: #121d2a;
    color: #dce8f0;
    border: 1px solid #26394c;
    border-radius: 8px;
    padding: 9px 14px;
}

QPushButton:hover {
    background: #18283a;
    border-color: #31516a;
}

QPushButton:pressed {
    background: #0e1823;
}

QPushButton#Primary {
    background: #139fd0;
    color: white;
    border: 1px solid #35caff;
    font-weight: 700;
}

QPushButton#Primary:hover {
    background: #20b5e7;
}

QPushButton#Danger {
    color: #ff8e8e;
    border-color: #57343a;
}

QPushButton#Nav {
    text-align: left;
    background: transparent;
    border: 1px solid transparent;
    color: #8395a7;
    padding: 11px 13px;
}

QPushButton#Nav:hover {
    background: #101c29;
    color: #dcebf4;
}

QPushButton#NavActive {
    text-align: left;
    background: #102b3a;
    border: 1px solid #15536e;
    color: #36caff;
    padding: 11px 13px;
    font-weight: 700;
}

QListWidget {
    background: transparent;
    border: none;
    outline: none;
}

QListWidget::item {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 9px;
    padding: 12px;
    margin: 2px 0;
}

QListWidget::item:hover {
    background: #101c29;
}

QListWidget::item:selected {
    background: #102b3a;
    border: 1px solid #15536e;
    color: #38caff;
}

QProgressBar {
    background: #111c29;
    border: none;
    border-radius: 4px;
    height: 7px;
}

QProgressBar::chunk {
    background: #27c7ff;
    border-radius: 4px;
}

QStatusBar {
    background: #0a1119;
    color: #6f8294;
    border-top: 1px solid #182534;
}
"""


def make_card() -> QFrame:
    card = QFrame()
    card.setObjectName("Card")
    return card


def make_stat_card(
    number: str,
    caption: str,
    color: str = "#f2f7fb",
) -> QFrame:
    card = QFrame()
    card.setObjectName("StatCard")

    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(4)

    number_label = QLabel(number)
    number_label.setObjectName("StatNumber")
    number_label.setStyleSheet(
        f"color: {color};"
    )

    caption_label = QLabel(caption)
    caption_label.setObjectName("StatCaption")

    layout.addWidget(number_label)
    layout.addWidget(caption_label)

    return card


# ============================================================
# SETUP DIALOG
# ============================================================

class SetupDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()

        self.result_password = ""

        self.setWindowTitle("PicklePass - First Setup")
        self.setMinimumSize(500, 430)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(35, 30, 35, 30)
        layout.setSpacing(14)

        title = QLabel("PicklePass")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Create the master password for your encrypted vault."
        )
        subtitle.setObjectName("PageSubtitle")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        layout.addSpacing(18)

        form = QFormLayout()
        form.setSpacing(12)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText(
            "Master password"
        )

        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm.setPlaceholderText(
            "Repeat master password"
        )

        form.addRow("Master password", self.password)
        form.addRow("Confirm password", self.confirm)

        layout.addLayout(form)

        self.strength = QLabel(
            "Use a long passphrase for better protection."
        )
        self.strength.setObjectName("PageSubtitle")
        layout.addWidget(self.strength)

        self.password.textChanged.connect(
            self.update_strength
        )

        layout.addStretch()

        create = QPushButton(
            "Create encrypted vault"
        )
        create.setObjectName("Primary")
        create.setMinimumHeight(44)
        create.clicked.connect(
            self.create_vault
        )

        layout.addWidget(create)

    def update_strength(self, password: str) -> None:
        length = len(password)

        if length == 0:
            text = "Use a long passphrase for better protection."
            color = "#71859a"
        elif length < 8:
            text = "Very weak"
            color = "#ff7777"
        elif length < 12:
            text = "Fair"
            color = "#ffbf5b"
        elif length < 16:
            text = "Good"
            color = "#7cdcff"
        else:
            text = "Strong"
            color = "#36df9a"

        self.strength.setText(text)
        self.strength.setStyleSheet(
            f"color: {color};"
        )

    def create_vault(self) -> None:
        password = self.password.text()
        confirmation = self.confirm.text()

        if len(password) < 1:
            QMessageBox.warning(
                self,
                "Password required",
                "Enter a master password.",
            )
            return

        if password != confirmation:
            QMessageBox.warning(
                self,
                "Passwords do not match",
                "The two passwords must match.",
            )
            return

        self.result_password = password
        self.accept()


# ============================================================
# LOGIN WINDOW
# ============================================================

class LoginWindow(QWidget):
    def __init__(
        self,
        vault: Vault,
        on_unlock,
    ) -> None:
        super().__init__()

        self.vault = vault
        self.on_unlock = on_unlock

        self.setWindowTitle(
            "PicklePass - Unlock"
        )
        self.setMinimumSize(540, 480)

        self.build_ui()

    def build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(70, 55, 70, 55)
        root.setSpacing(14)

        root.addStretch()

        logo = QLabel("🥒 PicklePass")
        logo.setObjectName("Logo")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(logo)

        subtitle = QLabel(
            "SECURE VAULT"
        )
        subtitle.setObjectName("Cyan")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet(
            "font-weight: 700; letter-spacing: 2px;"
        )
        root.addWidget(subtitle)

        root.addSpacing(18)

        card = make_card()
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(13)

        title = QLabel(
            "Unlock your vault"
        )
        title.setObjectName("PageTitle")
        card_layout.addWidget(title)

        info = QLabel(
            "Your vault is encrypted locally. "
            "Your master password is never stored."
        )
        info.setObjectName("PageSubtitle")
        info.setWordWrap(True)
        card_layout.addWidget(info)

        self.password = QLineEdit()
        self.password.setEchoMode(
            QLineEdit.EchoMode.Password
        )
        self.password.setPlaceholderText(
            "Master password"
        )
        self.password.setMinimumHeight(44)
        self.password.returnPressed.connect(
            self.unlock
        )
        card_layout.addWidget(self.password)

        unlock = QPushButton("Unlock vault")
        unlock.setObjectName("Primary")
        unlock.setMinimumHeight(44)
        unlock.clicked.connect(
            self.unlock
        )
        card_layout.addWidget(unlock)

        self.status = QLabel("")
        self.status.setWordWrap(True)
        self.status.setStyleSheet(
            "color: #ff7777;"
        )
        card_layout.addWidget(self.status)

        root.addWidget(card)

        security = QLabel(
            "●  AES-256-GCM    ●  Argon2id    ●  Local vault"
        )
        security.setAlignment(
            Qt.AlignmentFlag.AlignCenter
        )
        security.setObjectName("PageSubtitle")
        root.addWidget(security)

        root.addStretch()

    def unlock(self) -> None:
        password = self.password.text()

        if not password:
            self.status.setText(
                "Enter your master password."
            )
            return

        try:
            self.vault.unlock(password)

            self.password.clear()
            self.status.clear()

            self.hide()

            self.on_unlock(self.vault)

        except VaultError as exc:
            self.status.setText(str(exc))
            self.password.clear()
            self.password.setFocus()


# ============================================================
# ENTRY DIALOG
# ============================================================

class EntryDialog(QDialog):
    def __init__(
        self,
        entry: dict[str, Any] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)

        self.entry = entry or {}
        self.result: dict[str, Any] | None = None

        self.setWindowTitle(
            "Password Entry"
        )
        self.resize(620, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(12)

        title = QLabel(
            "Password entry"
        )
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        form = QFormLayout()
        form.setSpacing(11)

        self.name = QLineEdit(
            self.entry.get("name", "")
        )

        self.username = QLineEdit(
            self.entry.get("username", "")
        )

        self.password = QLineEdit(
            self.entry.get("password", "")
        )
        self.password.setEchoMode(
            QLineEdit.EchoMode.Password
        )

        password_row = QHBoxLayout()
        password_row.setSpacing(7)
        password_row.addWidget(
            self.password
        )

        generate = QPushButton("Generate")
        generate.clicked.connect(
            self.generate_password
        )
        password_row.addWidget(generate)

        self.url = QLineEdit(
            self.entry.get("url", "")
        )

        self.totp = QLineEdit(
            self.entry.get("totp_secret", "")
        )

        totp_row = QHBoxLayout()
        totp_row.setSpacing(7)
        totp_row.addWidget(self.totp)

        test_totp = QPushButton("Test")
        test_totp.clicked.connect(
            self.test_totp
        )
        totp_row.addWidget(test_totp)

        self.notes = QTextEdit()
        self.notes.setPlainText(
            self.entry.get("notes", "")
        )
        self.notes.setMinimumHeight(130)

        form.addRow("Name", self.name)
        form.addRow("Username", self.username)
        form.addRow("Password", password_row)
        form.addRow("Website", self.url)
        form.addRow("TOTP secret", totp_row)
        form.addRow("Notes", self.notes)

        layout.addLayout(form)

        hint = QLabel(
            "TOTP secrets are stored inside the encrypted vault."
        )
        hint.setObjectName("PageSubtitle")
        layout.addWidget(hint)

        layout.addStretch()

        buttons = QHBoxLayout()

        cancel = QPushButton("Cancel")
        cancel.clicked.connect(
            self.reject
        )

        save = QPushButton("Save entry")
        save.setObjectName("Primary")
        save.clicked.connect(
            self.save_entry
        )

        buttons.addWidget(cancel)
        buttons.addStretch()
        buttons.addWidget(save)

        layout.addLayout(buttons)

    def generate_password(self) -> None:
        self.password.setText(
            generate_password(28)
        )

    def test_totp(self) -> None:
        secret = self.totp.text().strip()

        if not secret:
            QMessageBox.information(
                self,
                "TOTP",
                "Enter a TOTP secret first.",
            )
            return

        try:
            code = pyotp.TOTP(secret).now()

            QMessageBox.information(
                self,
                "TOTP",
                f"Current code: {code}",
            )

        except Exception:
            QMessageBox.warning(
                self,
                "Invalid TOTP",
                "The TOTP secret could not be parsed.",
            )

    def save_entry(self) -> None:
        name = self.name.text().strip()
        secret = self.totp.text().strip()

        if not name:
            QMessageBox.warning(
                self,
                "Missing name",
                "Enter a name for this entry.",
            )
            return

        if secret:
            try:
                pyotp.TOTP(secret)
            except Exception:
                QMessageBox.warning(
                    self,
                    "Invalid TOTP",
                    "Check the TOTP secret.",
                )
                return

        self.result = {
            "name": name,
            "username": self.username.text(),
            "password": self.password.text(),
            "url": self.url.text(),
            "totp_secret": secret,
            "notes": self.notes.toPlainText(),
        }

        self.accept()


# ============================================================
# MAIN WINDOW
# ============================================================

class MainWindow(QMainWindow):
    def __init__(
        self,
        vault: Vault,
        on_lock,
    ) -> None:
        super().__init__()

        self.vault = vault
        self.on_lock = on_lock

        self.current_entry_id: str | None = None

        self.clipboard_timer: QTimer | None = None
        self.clipboard_value = ""

        self.last_activity = time.monotonic()

        self.setWindowTitle(
            "PicklePass"
        )
        self.resize(1240, 760)
        self.setMinimumSize(980, 650)

        self.build_ui()
        self.refresh_entries()
        self.update_dashboard()

        self.activity_timer = QTimer(self)
        self.activity_timer.timeout.connect(
            self.check_auto_lock
        )
        self.activity_timer.start(30_000)

        self.totp_timer = QTimer(self)
        self.totp_timer.timeout.connect(
            self.update_totp_display
        )
        self.totp_timer.start(1_000)

    # --------------------------------------------------------
    # ACTIVITY
    # --------------------------------------------------------

    def touch_activity(self) -> None:
        self.last_activity = time.monotonic()

    def check_auto_lock(self) -> None:
        settings = self.vault.data.get(
            "settings",
            {},
        )

        timeout_minutes = int(
            settings.get(
                "auto_lock_minutes",
                15,
            )
        )

        elapsed = (
            time.monotonic()
            - self.last_activity
        )

        if elapsed >= timeout_minutes * 60:
            self.lock_vault()

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------

    def build_ui(self) -> None:
        root = QWidget()
        self.setCentralWidget(root)

        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.build_sidebar(outer)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(
            28, 25, 28, 20
        )
        content_layout.setSpacing(18)

        self.pages = QStackedWidget()

        self.dashboard_page = self.build_dashboard()
        self.vault_page = self.build_vault_page()
        self.settings_page = self.build_settings_page()

        self.pages.addWidget(
            self.dashboard_page
        )
        self.pages.addWidget(
            self.vault_page
        )
        self.pages.addWidget(
            self.settings_page
        )

        content_layout.addWidget(
            self.pages
        )

        outer.addWidget(content, 1)

        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage(
            "Vault unlocked"
        )

    def build_sidebar(
        self,
        outer: QHBoxLayout,
    ) -> None:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(245)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(
            17, 22, 17, 18
        )
        layout.setSpacing(7)

        logo = QLabel("🥒 PicklePass")
        logo.setObjectName("Logo")
        layout.addWidget(logo)

        version = QLabel("PERSONAL SECURITY VAULT")
        version.setObjectName("PageSubtitle")
        layout.addWidget(version)

        layout.addSpacing(22)

        self.nav_dashboard = QPushButton(
            "▦   Dashboard"
        )
        self.nav_vault = QPushButton(
            "▣   Passwords"
        )
        self.nav_settings = QPushButton(
            "⚙   Settings"
        )

        for button in (
            self.nav_dashboard,
            self.nav_vault,
            self.nav_settings,
        ):
            button.setObjectName("Nav")
            button.setMinimumHeight(42)
            layout.addWidget(button)

        self.nav_dashboard.clicked.connect(
            lambda: self.switch_page(0)
        )
        self.nav_vault.clicked.connect(
            lambda: self.switch_page(1)
        )
        self.nav_settings.clicked.connect(
            lambda: self.switch_page(2)
        )

        layout.addSpacing(18)

        security_label = QLabel("SECURITY")
        security_label.setObjectName("SectionTitle")
        layout.addWidget(security_label)

        security_card = QFrame()
        security_card.setObjectName("StatCard")

        security_layout = QVBoxLayout(
            security_card
        )
        security_layout.setContentsMargins(
            12, 12, 12, 12
        )
        security_layout.setSpacing(7)

        secure = QLabel("●  VAULT UNLOCKED")
        secure.setObjectName("Green")
        secure.setStyleSheet(
            "font-weight: 700;"
        )

        encryption = QLabel(
            "AES-256-GCM\nArgon2id"
        )
        encryption.setObjectName(
            "PageSubtitle"
        )

        security_layout.addWidget(secure)
        security_layout.addWidget(encryption)

        layout.addWidget(security_card)

        layout.addStretch()

        lock = QPushButton(
            "🔒  Lock vault"
        )
        lock.setObjectName("Danger")
        lock.setMinimumHeight(43)
        lock.clicked.connect(
            self.lock_vault
        )

        layout.addWidget(lock)

        outer.addWidget(sidebar)

        self.set_active_nav(
            self.nav_dashboard
        )

    def set_active_nav(
        self,
        active: QPushButton,
    ) -> None:
        for button in (
            self.nav_dashboard,
            self.nav_vault,
            self.nav_settings,
        ):
            button.setObjectName(
                "NavActive"
                if button is active
                else "Nav"
            )

            button.style().unpolish(button)
            button.style().polish(button)

    def switch_page(self, index: int) -> None:
        self.touch_activity()

        self.pages.setCurrentIndex(index)

        buttons = [
            self.nav_dashboard,
            self.nav_vault,
            self.nav_settings,
        ]

        self.set_active_nav(
            buttons[index]
        )

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    def build_dashboard(self) -> QWidget:
        page = QWidget()

        layout = QVBoxLayout(page)
        layout.setSpacing(18)

        header = QHBoxLayout()

        title_box = QVBoxLayout()

        title = QLabel("Security dashboard")
        title.setObjectName("PageTitle")

        subtitle = QLabel(
            "Overview of your local encrypted password vault."
        )
        subtitle.setObjectName("PageSubtitle")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        header.addLayout(title_box)
        header.addStretch()

        new_button = QPushButton(
            "+  New password"
        )
        new_button.setObjectName("Primary")
        new_button.clicked.connect(
            self.new_entry
        )

        header.addWidget(new_button)

        layout.addLayout(header)

        stats = QHBoxLayout()
        stats.setSpacing(12)

        self.stat_passwords = make_stat_card(
            "0",
            "Saved passwords",
            "#27c7ff",
        )

        self.stat_totp = make_stat_card(
            "0",
            "TOTP protected",
            "#36df9a",
        )

        self.stat_backup = make_stat_card(
            "Ready",
            "Encrypted backup",
            "#ffbf5b",
        )

        stats.addWidget(self.stat_passwords)
        stats.addWidget(self.stat_totp)
        stats.addWidget(self.stat_backup)

        layout.addLayout(stats)

        lower = QHBoxLayout()
        lower.setSpacing(14)

        activity_card = make_card()
        activity_layout = QVBoxLayout(
            activity_card
        )
        activity_layout.setContentsMargins(
            20, 18, 20, 18
        )

        activity_title = QLabel(
            "Vault status"
        )
        activity_title.setObjectName(
            "SectionTitle"
        )

        activity_layout.addWidget(
            activity_title
        )

        status_title = QLabel(
            "Your vault is currently unlocked"
        )
        status_title.setObjectName(
            "PageTitle"
        )
        status_title.setStyleSheet(
            "font-size: 19px;"
        )

        activity_layout.addWidget(
            status_title
        )

        status_info = QLabel(
            "Encryption: AES-256-GCM\n"
            "Key derivation: Argon2id\n"
            "Storage: local encrypted vault"
        )
        status_info.setObjectName(
            "PageSubtitle"
        )

        activity_layout.addWidget(
            status_info
        )

        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(100)
        progress.setTextVisible(False)

        activity_layout.addWidget(progress)

        lower.addWidget(
            activity_card,
            2,
        )

        tips_card = make_card()
        tips_layout = QVBoxLayout(
            tips_card
        )
        tips_layout.setContentsMargins(
            20, 18, 20, 18
        )

        tips_title = QLabel(
            "Quick actions"
        )
        tips_title.setObjectName(
            "SectionTitle"
        )

        tips_layout.addWidget(tips_title)

        search_button = QPushButton(
            "Open password vault"
        )
        search_button.clicked.connect(
            lambda: self.switch_page(1)
        )

        lock_button = QPushButton(
            "Lock vault now"
        )
        lock_button.clicked.connect(
            self.lock_vault
        )

        tips_layout.addWidget(search_button)
        tips_layout.addWidget(lock_button)

        tips_layout.addStretch()

        lower.addWidget(
            tips_card,
            1,
        )

        layout.addLayout(lower)
        layout.addStretch()

        return page

    # --------------------------------------------------------
    # VAULT PAGE
    # --------------------------------------------------------

    def build_vault_page(self) -> QWidget:
        page = QWidget()

        layout = QVBoxLayout(page)
        layout.setSpacing(15)

        header = QHBoxLayout()

        title_box = QVBoxLayout()

        title = QLabel("Passwords")
        title.setObjectName("PageTitle")

        subtitle = QLabel(
            "Manage credentials stored in your encrypted vault."
        )
        subtitle.setObjectName("PageSubtitle")

        title_box.addWidget(title)
        title_box.addWidget(subtitle)

        header.addLayout(title_box)
        header.addStretch()

        new_button = QPushButton(
            "+  New password"
        )
        new_button.setObjectName("Primary")
        new_button.clicked.connect(
            self.new_entry
        )

        header.addWidget(new_button)

        layout.addLayout(header)

        body = QHBoxLayout()
        body.setSpacing(14)

        left = make_card()
        left.setMinimumWidth(290)

        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(
            13, 13, 13, 13
        )

        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "⌕  Search passwords..."
        )
        self.search.textChanged.connect(
            self.refresh_entries
        )

        left_layout.addWidget(
            self.search
        )

        self.entry_list = QListWidget()
        self.entry_list.currentItemChanged.connect(
            self.select_entry
        )

        left_layout.addWidget(
            self.entry_list
        )

        body.addWidget(
            left,
            1,
        )

        right = make_card()

        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(
            22, 20, 22, 20
        )

        self.detail_title = QLabel(
            "Select a password"
        )
        self.detail_title.setObjectName(
            "PageTitle"
        )

        right_layout.addWidget(
            self.detail_title
        )

        self.detail_subtitle = QLabel(
            "Choose an entry from the list."
        )
        self.detail_subtitle.setObjectName(
            "PageSubtitle"
        )

        right_layout.addWidget(
            self.detail_subtitle
        )

        right_layout.addSpacing(12)

        self.detail_username = QLineEdit()
        self.detail_username.setReadOnly(True)

        self.detail_password = QLineEdit()
        self.detail_password.setReadOnly(True)
        self.detail_password.setEchoMode(
            QLineEdit.EchoMode.Password
        )

        self.detail_url = QLineEdit()
        self.detail_url.setReadOnly(True)

        self.detail_totp = QLineEdit()
        self.detail_totp.setReadOnly(True)

        self.detail_notes = QTextEdit()
        self.detail_notes.setReadOnly(True)
        self.detail_notes.setMaximumHeight(140)

        form = QFormLayout()
        form.setSpacing(10)

        form.addRow(
            "Username",
            self.detail_username,
        )
        form.addRow(
            "Password",
            self.detail_password,
        )
        form.addRow(
            "Website",
            self.detail_url,
        )
        form.addRow(
            "TOTP",
            self.detail_totp,
        )
        form.addRow(
            "Notes",
            self.detail_notes,
        )

        right_layout.addLayout(form)

        right_layout.addSpacing(8)

        buttons = QHBoxLayout()

        copy_user = QPushButton(
            "Copy username"
        )
        copy_user.clicked.connect(
            lambda: self.secure_copy(
                self.detail_username.text()
            )
        )

        copy_password = QPushButton(
            "Copy password"
        )
        copy_password.clicked.connect(
            lambda: self.secure_copy(
                self.detail_password.text()
            )
        )

        copy_totp = QPushButton(
            "Copy TOTP"
        )
        copy_totp.clicked.connect(
            self.copy_totp
        )

        edit = QPushButton("Edit")
        edit.clicked.connect(
            self.edit_entry
        )

        delete = QPushButton("Delete")
        delete.setObjectName("Danger")
        delete.clicked.connect(
            self.delete_entry
        )

        buttons.addWidget(copy_user)
        buttons.addWidget(copy_password)
        buttons.addWidget(copy_totp)
        buttons.addStretch()
        buttons.addWidget(edit)
        buttons.addWidget(delete)

        right_layout.addLayout(buttons)

        self.totp_status = QLabel("")
        self.totp_status.setObjectName(
            "PageSubtitle"
        )

        right_layout.addWidget(
            self.totp_status
        )

        right_layout.addStretch()

        body.addWidget(
            right,
            2,
        )

        layout.addLayout(body)

        return page

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    def build_settings_page(self) -> QWidget:
        page = QWidget()

        layout = QVBoxLayout(page)
        layout.setSpacing(18)

        title = QLabel("Settings")
        title.setObjectName("PageTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Configure local vault behavior."
        )
        subtitle.setObjectName("PageSubtitle")
        layout.addWidget(subtitle)

        card = make_card()

        form = QFormLayout(card)
        form.setContentsMargins(
            22, 22, 22, 22
        )
        form.setSpacing(13)

        self.autolock = QLineEdit()
        self.autolock.setPlaceholderText(
            "Minutes"
        )

        current_timeout = self.vault.data.get(
            "settings",
            {},
        ).get(
            "auto_lock_minutes",
            15,
        )

        self.autolock.setText(
            str(current_timeout)
        )

        save_settings = QPushButton(
            "Save settings"
        )
        save_settings.setObjectName(
            "Primary"
        )
        save_settings.clicked.connect(
            self.save_settings
        )

        form.addRow(
            "Auto-lock after",
            self.autolock,
        )
        form.addRow(
            "",
            save_settings,
        )

        layout.addWidget(card)

        info = make_card()

        info_layout = QVBoxLayout(info)
        info_layout.setContentsMargins(
            22, 20, 22, 20
        )

        info_title = QLabel(
            "Cryptography"
        )
        info_title.setObjectName(
            "SectionTitle"
        )

        info_text = QLabel(
            "Vault contents use AES-256-GCM.\n"
            "The master password is processed with Argon2id.\n"
            "A randomly generated data key is wrapped by the password-derived key."
        )
        info_text.setObjectName(
            "PageSubtitle"
        )
        info_text.setWordWrap(True)

        info_layout.addWidget(info_title)
        info_layout.addWidget(info_text)

        layout.addWidget(info)

        layout.addStretch()

        return page

    # --------------------------------------------------------
    # ENTRIES
    # --------------------------------------------------------

    def refresh_entries(self) -> None:
        if not hasattr(
            self,
            "entry_list",
        ):
            return

        query = ""

        if hasattr(self, "search"):
            query = self.search.text().lower()

        self.entry_list.clear()

        for entry in self.vault.entries():
            searchable = " ".join(
                [
                    str(entry.get("name", "")),
                    str(entry.get("username", "")),
                    str(entry.get("url", "")),
                ]
            ).lower()

            if query and query not in searchable:
                continue

            item = QListWidgetItem(
                entry.get(
                    "name",
                    "Unnamed",
                )
            )

            item.setData(
                Qt.ItemDataRole.UserRole,
                entry.get("id"),
            )

            self.entry_list.addItem(item)

        self.update_dashboard()

    def find_entry(
        self,
        entry_id: str | None,
    ) -> dict[str, Any] | None:
        if not entry_id:
            return None

        for entry in self.vault.entries():
            if entry.get("id") == entry_id:
                return entry

        return None

    def select_entry(
        self,
        current,
        previous,
    ) -> None:
        if current is None:
            return

        self.touch_activity()

        entry_id = current.data(
            Qt.ItemDataRole.UserRole
        )

        entry = self.find_entry(entry_id)

        if entry is None:
            return

        self.current_entry_id = entry_id

        self.detail_title.setText(
            entry.get(
                "name",
                "Entry",
            )
        )

        username = entry.get(
            "username",
            "",
        )

        url = entry.get(
            "url",
            "",
        )

        self.detail_subtitle.setText(
            url or username or "Password entry"
        )

        self.detail_username.setText(
            username
        )

        self.detail_password.setText(
            entry.get(
                "password",
                "",
            )
        )

        self.detail_url.setText(
            url
        )

        self.detail_notes.setPlainText(
            entry.get(
                "notes",
                "",
            )
        )

        self.update_totp_display()

    # --------------------------------------------------------
    # TOTP
    # --------------------------------------------------------

    def update_totp_display(self) -> None:
        entry = self.find_entry(
            self.current_entry_id
        )

        if not entry:
            if hasattr(self, "detail_totp"):
                self.detail_totp.clear()
            return

        secret = entry.get(
            "totp_secret",
            "",
        )

        if not secret:
            self.detail_totp.setText(
                "Not configured"
            )
            self.totp_status.setText("")
            return

        try:
            totp = pyotp.TOTP(secret)

            code = totp.now()

            remaining = (
                totp.interval
                - int(time.time()) % totp.interval
            )

            self.detail_totp.setText(
                code
            )

            self.totp_status.setText(
                f"Authenticator code refreshes in {remaining}s"
            )

        except Exception:
            self.detail_totp.setText(
                "Invalid TOTP secret"
            )
            self.totp_status.setText("")

    def copy_totp(self) -> None:
        self.touch_activity()

        entry = self.find_entry(
            self.current_entry_id
        )

        if not entry:
            return

        secret = entry.get(
            "totp_secret",
            "",
        )

        if not secret:
            return

        try:
            code = pyotp.TOTP(secret).now()
            self.secure_copy(code)

        except Exception:
            QMessageBox.warning(
                self,
                "TOTP error",
                "Could not generate the TOTP code.",
            )

    # --------------------------------------------------------
    # CREATE / EDIT / DELETE
    # --------------------------------------------------------

    def new_entry(self) -> None:
        self.touch_activity()

        dialog = EntryDialog(
            parent=self
        )

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        if dialog.result is None:
            return

        try:
            self.vault.add_entry(
                dialog.result
            )

            self.refresh_entries()

            self.status.showMessage(
                "Password saved.",
                3000,
            )

            self.switch_page(1)

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Save failed",
                str(exc),
            )

    def edit_entry(self) -> None:
        self.touch_activity()

        if not self.current_entry_id:
            return

        entry = self.find_entry(
            self.current_entry_id
        )

        if entry is None:
            return

        dialog = EntryDialog(
            entry,
            self,
        )

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        if dialog.result is None:
            return

        try:
            self.vault.update_entry(
                self.current_entry_id,
                dialog.result,
            )

            self.refresh_entries()

            self.status.showMessage(
                "Password updated.",
                3000,
            )

            self.select_current_entry()

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Update failed",
                str(exc),
            )

    def select_current_entry(self) -> None:
        if not self.current_entry_id:
            return

        for index in range(
            self.entry_list.count()
        ):
            item = self.entry_list.item(index)

            if item.data(
                Qt.ItemDataRole.UserRole
            ) == self.current_entry_id:
                self.entry_list.setCurrentItem(
                    item
                )
                return

    def delete_entry(self) -> None:
        self.touch_activity()

        if not self.current_entry_id:
            return

        answer = QMessageBox.question(
            self,
            "Delete password",
            "Permanently delete this entry?",
            QMessageBox.StandardButton.Yes
            | QMessageBox.StandardButton.No,
        )

        if answer != QMessageBox.StandardButton.Yes:
            return

        try:
            self.vault.delete_entry(
                self.current_entry_id
            )

            self.current_entry_id = None

            self.detail_title.setText(
                "Select a password"
            )

            self.detail_subtitle.setText(
                "Choose an entry from the list."
            )

            self.detail_username.clear()
            self.detail_password.clear()
            self.detail_url.clear()
            self.detail_totp.clear()
            self.detail_notes.clear()
            self.totp_status.clear()

            self.refresh_entries()

            self.status.showMessage(
                "Entry deleted.",
                3000,
            )

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Delete failed",
                str(exc),
            )

    # --------------------------------------------------------
    # SETTINGS
    # --------------------------------------------------------

    def save_settings(self) -> None:
        try:
            minutes = int(
                self.autolock.text()
            )

            if minutes < 1:
                raise ValueError

            if minutes > 1440:
                raise ValueError

            settings = self.vault.data.setdefault(
                "settings",
                {},
            )

            settings["auto_lock_minutes"] = minutes

            self.vault.save()

            self.status.showMessage(
                "Settings saved.",
                3000,
            )

        except ValueError:
            QMessageBox.warning(
                self,
                "Invalid value",
                "Auto-lock must be between 1 and 1440 minutes.",
            )

        except Exception as exc:
            QMessageBox.critical(
                self,
                "Settings error",
                str(exc),
            )

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    def update_dashboard(self) -> None:
        if not hasattr(
            self,
            "stat_passwords",
        ):
            return

        entries = self.vault.entries()

        totp_count = sum(
            1
            for entry in entries
            if entry.get("totp_secret")
        )

        self.set_stat_number(
            self.stat_passwords,
            str(len(entries)),
        )

        self.set_stat_number(
            self.stat_totp,
            str(totp_count),
        )

    @staticmethod
    def set_stat_number(
        card: QFrame,
        value: str,
    ) -> None:
        layout = card.layout()

        if layout is None:
            return

        label = layout.itemAt(0).widget()

        if isinstance(label, QLabel):
            label.setText(value)

    # --------------------------------------------------------
    # CLIPBOARD
    # --------------------------------------------------------

    def secure_copy(self, text: str) -> None:
        if not text:
            return

        self.touch_activity()

        clipboard = QApplication.clipboard()

        clipboard.setText(text)

        self.clipboard_value = text

        if self.clipboard_timer is not None:
            self.clipboard_timer.stop()

        self.clipboard_timer = QTimer(self)
        self.clipboard_timer.setSingleShot(True)

        self.clipboard_timer.timeout.connect(
            self.clear_clipboard
        )

        self.clipboard_timer.start(
            20_000
        )

        self.status.showMessage(
            "Copied. Clipboard will clear in 20 seconds.",
            3000,
        )

    def clear_clipboard(self) -> None:
        clipboard = QApplication.clipboard()

        if clipboard.text() == self.clipboard_value:
            clipboard.clear()

        self.clipboard_value = ""

        self.status.showMessage(
            "Clipboard cleared.",
            3000,
        )

    # --------------------------------------------------------
    # LOCK
    # --------------------------------------------------------

    def lock_vault(self) -> None:
        self.touch_activity()

        if self.clipboard_timer is not None:
            self.clipboard_timer.stop()

        self.clear_clipboard()

        self.vault.lock()

        self.close()

        self.on_lock()


# ============================================================
# APPLICATION CONTROLLER
# ============================================================

class PicklePassApp:
    def __init__(self) -> None:
        self.app = QApplication(sys.argv)

        self.app.setApplicationName(
            APP_NAME
        )

        self.app.setStyleSheet(STYLE)

        self.vault = Vault()

        self.login: LoginWindow | None = None
        self.main_window: MainWindow | None = None

    def create_first_vault(self) -> bool:
        setup = SetupDialog()

        if setup.exec() != QDialog.DialogCode.Accepted:
            return False

        password = setup.result_password

        try:
            self.vault.create(password)
            self.vault.lock()

        except Exception as exc:
            QMessageBox.critical(
                None,
                "Vault creation failed",
                str(exc),
            )
            return False

        QMessageBox.information(
            None,
            "PicklePass ready",
            "Your encrypted vault has been created.\n\n"
            "Unlock it using your master password.",
        )

        return True

    def validate_existing_vault(self) -> bool:
        try:
            raw = VAULT_FILE.read_bytes()

            if not raw.startswith(MAGIC):
                QMessageBox.critical(
                    None,
                    "Invalid vault",
                    "The existing vault is not a "
                    "recognized PicklePass vault.",
                )
                return False

            return True

        except Exception as exc:
            QMessageBox.critical(
                None,
                "Vault error",
                f"Could not inspect the vault.\n\n"
                f"{type(exc).__name__}: {exc}",
            )

            return False

    def show_login(self) -> None:
        if self.main_window is not None:
            self.main_window.close()
            self.main_window = None

        self.login = LoginWindow(
            self.vault,
            self.show_main,
        )

        self.login.show()
        self.login.raise_()
        self.login.activateWindow()

    def show_main(
        self,
        vault: Vault,
    ) -> None:
        if self.login is not None:
            self.login.hide()

        self.main_window = MainWindow(
            vault,
            self.locked,
        )

        self.main_window.show()
        self.main_window.raise_()
        self.main_window.activateWindow()

    def locked(self) -> None:
        self.main_window = None

        self.vault.lock()

        self.show_login()

    def run(self) -> int:
        if not VAULT_FILE.exists():
            if not self.create_first_vault():
                return 0

        else:
            if not self.validate_existing_vault():
                return 1

        self.show_login()

        return self.app.exec()


# ============================================================
# ENTRY POINT
# ============================================================

def main() -> int:
    controller = PicklePassApp()

    return controller.run()


if __name__ == "__main__":
    try:
        sys.exit(main())

    except Exception as exc:
        try:
            QMessageBox.critical(
                None,
                "PicklePass error",
                "PicklePass encountered an unexpected error.\n\n"
                f"{type(exc).__name__}: {exc}",
            )

        except Exception:
            print(
                "PicklePass error:",
                exc,
            )

        sys.exit(1)