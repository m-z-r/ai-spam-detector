# ============================================================
# MESSAGE GUARD (by AI)
# Smarter Detection, Safer Decisions.
# ============================================================
#
# This is the main Python application for Message Guard.
#
# The program combines:
#   1. CustomTkinter GUI
#   2. Message security analysis
#   3. URL analysis
#   4. SQLite permanent storage
#   5. Encryption for saved messages
#   6. Searchable scan history
#   7. Analytics
#   8. Arduino communication
#
# IMPORTANT:
# Message Guard is an AI-assisted security tool.
# Its result is a warning, not a guarantee.
# The user should always make the final decision.
# ============================================================


# ============================================================
# 1. IMPORTS
# ============================================================

# os is used for accessing the Windows username and file paths.
import os

# re is used for detecting URLs inside messages.
import re

# sqlite3 provides a permanent local database.
import sqlite3

# threading allows scanning to happen without freezing the GUI.
import threading

# time is used for Arduino communication delays.
import time

# base64 and hashlib help create a stable encryption key.
import base64
import hashlib

# datetime records the date and time of every saved scan.
from datetime import datetime

# urlparse helps us inspect website domains.
from urllib.parse import urlparse

# tkinter provides basic message boxes.
import tkinter as tk
from tkinter import messagebox

# CustomTkinter provides the modern graphical interface.
import customtkinter as ctk

# pyserial allows Python to communicate with Arduino.
import serial

# requests is used for optional online URL checking.
import requests

# Fernet provides encryption for saved message content.
from cryptography.fernet import Fernet

# Matplotlib creates the analytics chart.
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


# ============================================================
# 2. ARDUINO SETTINGS
# ============================================================

# CHANGE THIS to the COM port shown by Arduino IDE.
#
# Example:
#
# Arduino IDE → Tools → Port → COM4
#
# Then write:
#
# ARDUINO_PORT = "COM4"
#
ARDUINO_PORT = "COM3"

# This must match Serial.begin(9600) in Arduino.
BAUD_RATE = 9600


# ============================================================
# 3. OPTIONAL VIRUSTOTAL API
# ============================================================
#
# You can leave this empty.
#
# Message Guard will still perform local URL analysis.
#
# If you later receive a VirusTotal API key, put it here.
#
# NEVER publish your private API key on GitHub.
# ============================================================

VIRUSTOTAL_API_KEY = ""


# ============================================================
# 4. APPLICATION COLORS
# ============================================================

NAVY = "#071A33"
NAVY_LIGHT = "#0D294A"
NAVY_CARD = "#102D4D"
NAVY_INPUT = "#081F38"

WHITE = "#FFFFFF"
OFF_WHITE = "#F5F7FA"

GOLD = "#D4AF37"
GOLD_LIGHT = "#E8C766"

MUTED = "#AAB8C7"

RED = "#E63946"
RED_LIGHT = "#FF6B6B"

YELLOW = "#F4C542"
YELLOW_LIGHT = "#FFE082"

GREEN = "#2FBF71"
GREEN_LIGHT = "#65D99A"


# ============================================================
# 5. SUSPICIOUS WORDS
# ============================================================
#
# These words are warning indicators.
#
# A word alone does NOT prove that a message is a scam.
# Multiple indicators are considered together.
# ============================================================

SCAM_WORDS = [
    "urgent",
    "immediately",
    "winner",
    "won",
    "prize",
    "free",
    "money",
    "cash",
    "lottery",
    "click",
    "claim",
    "verify",
    "password",
    "bank",
    "credit card",
    "send money",
    "pay now",
    "gift card",
    "investment",
    "guaranteed",
    "congratulations",
    "otp",
    "account suspended",
    "account blocked",
    "limited time",
    "act now",
    "security alert",
    "verify account",
    "confirm identity",
    "payment required"
]


# ============================================================
# 6. DATABASE MANAGER
# ============================================================
#
# SQLite is used because it provides permanent local storage.
#
# The database file is automatically created:
#
#     message_guard.db
#
# It remains available after the application closes.
# ============================================================

class DatabaseManager:

    def __init__(self):

        # The database is stored in the same folder
        # where the Python program is running.
        self.database = "message_guard.db"

        # Create/open the SQLite database.
        self.connection = sqlite3.connect(
            self.database,
            check_same_thread=False
        )

        # Create the required table.
        self.create_tables()


    # --------------------------------------------------------
    # CREATE TABLE
    # --------------------------------------------------------

    def create_tables(self):

        cursor = self.connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                encrypted_message TEXT NOT NULL,

                result TEXT NOT NULL,

                why TEXT,

                suggestion TEXT,

                detected_words TEXT,

                url_result TEXT,

                timestamp TEXT NOT NULL
            )
        """)

        self.connection.commit()


    # --------------------------------------------------------
    # SAVE SCAN
    # --------------------------------------------------------

    def save_scan(
        self,
        encrypted_message,
        result,
        why,
        suggestion,
        detected_words,
        url_result
    ):

        cursor = self.connection.cursor()

        cursor.execute(
            """
            INSERT INTO scans
            (
                encrypted_message,
                result,
                why,
                suggestion,
                detected_words,
                url_result,
                timestamp
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                encrypted_message,
                result,
                why,
                suggestion,
                detected_words,
                url_result,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        self.connection.commit()


    # --------------------------------------------------------
    # GET ALL SCANS
    # --------------------------------------------------------

    def get_scans(self):

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT
                id,
                encrypted_message,
                result,
                why,
                suggestion,
                detected_words,
                url_result,
                timestamp
            FROM scans
            ORDER BY id DESC
            """
        )

        return cursor.fetchall()


    # --------------------------------------------------------
    # DELETE ONE SCAN
    # --------------------------------------------------------

    def delete_scan(self, scan_id):

        self.connection.execute(
            "DELETE FROM scans WHERE id = ?",
            (scan_id,)
        )

        self.connection.commit()


    # --------------------------------------------------------
    # DELETE ALL SCANS
    # --------------------------------------------------------

    def delete_all(self):

        self.connection.execute(
            "DELETE FROM scans"
        )

        self.connection.commit()


    # --------------------------------------------------------
    # GET STATISTICS
    # --------------------------------------------------------

    def get_statistics(self):

        cursor = self.connection.cursor()

        cursor.execute(
            """
            SELECT result, COUNT(*)
            FROM scans
            GROUP BY result
            """
        )

        return cursor.fetchall()


    # --------------------------------------------------------
    # CLOSE DATABASE
    # --------------------------------------------------------

    def close(self):

        self.connection.close()


# ============================================================
# 7. ENCRYPTION MANAGER
# ============================================================
#
# Messages can contain private information.
#
# Therefore, the message is encrypted BEFORE being saved.
#
# SQLite stores the encrypted version rather than plain text.
# ============================================================

class EncryptionManager:

    def __init__(self):

        # Use the Windows username to create a stable local key.
        username = os.environ.get(
            "USERNAME",
            "message_guard"
        )

        source = (
            username
            + "_message_guard_local_key"
        )

        # SHA-256 creates a fixed-length cryptographic hash.
        digest = hashlib.sha256(
            source.encode()
        ).digest()

        # Fernet requires a URL-safe base64 key.
        key = base64.urlsafe_b64encode(
            digest
        )

        self.fernet = Fernet(key)


    # --------------------------------------------------------
    # ENCRYPT MESSAGE
    # --------------------------------------------------------

    def encrypt(self, message):

        return self.fernet.encrypt(
            message.encode()
        ).decode()


    # --------------------------------------------------------
    # DECRYPT MESSAGE
    # --------------------------------------------------------

    def decrypt(self, encrypted_message):

        try:

            return self.fernet.decrypt(
                encrypted_message.encode()
            ).decode()

        except Exception:

            return "[Unable to decrypt message]"


# ============================================================
# 8. URL ANALYZER
# ============================================================

class URLAnalyzer:

    def __init__(self):

        # This pattern searches for HTTP, HTTPS and www links.
        self.pattern = re.compile(
            r"https?://[^\s]+|www\.[^\s]+",
            re.IGNORECASE
        )


    # --------------------------------------------------------
    # EXTRACT URLS
    # --------------------------------------------------------

    def extract_urls(self, message):

        return self.pattern.findall(
            message
        )


    # --------------------------------------------------------
    # LOCAL URL ANALYSIS
    # --------------------------------------------------------

    def check_url(self, url):

        # Remove punctuation that may appear after a URL.
        cleaned = url.rstrip(
            ".,!?;:)"
        )

        # Add HTTPS if the URL starts with www.
        if cleaned.startswith("www."):

            cleaned = (
                "https://"
                + cleaned
            )

        try:

            parsed = urlparse(
                cleaned
            )

            domain = parsed.netloc.lower()

        except Exception:

            return "INVALID URL"


        # These are examples of URL patterns that deserve
        # additional caution.
        suspicious_patterns = [

            "bit.ly",
            "tinyurl",
            "grabify",
            "login-",
            "-login",
            "-verify",
            "verify-",
            "-secure",
            "free-prize",
            "account-verify"
        ]


        for pattern in suspicious_patterns:

            if pattern in domain:

                return "SUSPICIOUS URL"


        return "URL DETECTED"


    # --------------------------------------------------------
    # OPTIONAL VIRUSTOTAL CHECK
    # --------------------------------------------------------

    def virus_total_check(self, url):

        # If no API key exists, skip online checking.
        if not VIRUSTOTAL_API_KEY:

            return None

        try:

            # VirusTotal uses a URL-safe encoded URL ID.
            encoded = base64.urlsafe_b64encode(
                url.encode()
            ).decode().strip("=")

            endpoint = (
                "https://www.virustotal.com/api/v3/urls/"
                + encoded
            )

            response = requests.get(
                endpoint,
                headers={
                    "x-apikey":
                    VIRUSTOTAL_API_KEY
                },
                timeout=8
            )

            if response.status_code != 200:

                return None

            data = response.json()

            stats = (
                data
                .get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )

            malicious = stats.get(
                "malicious",
                0
            )

            suspicious = stats.get(
                "suspicious",
                0
            )


            if malicious > 0:

                return "MALICIOUS URL"


            if suspicious > 0:

                return "SUSPICIOUS URL"


            return "URL CLEAN"

        except Exception:

            return None


# ============================================================
# 9. MESSAGE ANALYZER
# ============================================================

class MessageAnalyzer:

    def __init__(
        self,
        url_analyzer
    ):

        self.url_analyzer = url_analyzer


    # --------------------------------------------------------
    # ANALYZE MESSAGE
    # --------------------------------------------------------

    def analyze(self, message):

        text = message.lower()

        detected_words = []

        score = 0


        # ====================================================
        # KEYWORD ANALYSIS
        # ====================================================

        for word in SCAM_WORDS:

            if word in text:

                detected_words.append(
                    word
                )

                score += 1


        # ====================================================
        # URL ANALYSIS
        # ====================================================

        urls = self.url_analyzer.extract_urls(
            message
        )

        url_results = []


        for url in urls:

            result = self.url_analyzer.check_url(
                url
            )

            url_results.append(
                result
            )

            # Suspicious URLs carry more weight because
            # phishing links are an important warning sign.
            if result == "SUSPICIOUS URL":

                score += 3


        # ====================================================
        # CLASSIFICATION
        # ====================================================

        if score >= 5:

            risk = "HIGH"

            why = (
                "Multiple warning signs were detected. "
                "The message may contain pressure, financial "
                "requests, sensitive-information requests, "
                "or suspicious links."
            )

            suggestion = (
                "Do not click suspicious links or share "
                "passwords, OTPs, banking information, "
                "or money. Verify the sender independently."
            )


        elif score >= 2:

            risk = "SUSPICIOUS"

            why = (
                "Several warning signs were detected. "
                "The message may require additional "
                "verification before you respond."
            )

            suggestion = (
                "Be cautious. Verify the sender and "
                "information through an official source "
                "before taking action."
            )


        else:

            risk = "LOW"

            why = (
                "No major scam indicators were detected "
                "by the current analysis."
            )

            suggestion = (
                "The message appears low risk, but always "
                "use your own judgement before sharing "
                "personal information."
            )


        return {
            "result": risk,
            "score": score,
            "detected": detected_words,
            "urls": urls,
            "url_results": url_results,
            "why": why,
            "suggestion": suggestion
        }


# ============================================================
# 10. ARDUINO MANAGER
# ============================================================
#
# Python communicates with Arduino using Serial.
#
# Python sends:
#
# HIGH
# SUSPICIOUS
# LOW
#
# Arduino then controls:
#
# HIGH       → 🔴 LED + buzzer + LCD
# SUSPICIOUS → 🟡 LED + LCD
# LOW        → 🟢 LED + LCD
# ============================================================

class ArduinoManager:

    def __init__(self):

        self.connection = None

        self.connected = False


        try:

            self.connection = serial.Serial(
                ARDUINO_PORT,
                BAUD_RATE,
                timeout=1
            )

            # Arduino resets briefly when serial connection opens.
            time.sleep(2)

            self.connected = True

        except Exception:

            # The GUI can still work without Arduino.
            self.connected = False


    # --------------------------------------------------------
    # SEND RESULT
    # --------------------------------------------------------

    def send(self, result):

        if not self.connected:

            return


        try:

            self.connection.write(
                (result + "\n").encode()
            )

        except Exception:

            self.connected = False


    # --------------------------------------------------------
    # CLOSE CONNECTION
    # --------------------------------------------------------

    def close(self):

        if self.connection:

            try:

                self.connection.close()

            except Exception:

                pass


# ============================================================
# 11. MAIN APPLICATION
# ============================================================

class MessageGuardApp:

    def __init__(self):

        # Database handles permanent storage.
        self.database = DatabaseManager()

        # Encryption handles secure message storage.
        self.encryption = EncryptionManager()

        # URL analyzer checks links.
        self.url_analyzer = URLAnalyzer()

        # Message analyzer performs the main detection.
        self.analyzer = MessageAnalyzer(
            self.url_analyzer
        )

        # Arduino manager handles physical output.
        self.arduino = ArduinoManager()

        # Stores the latest scan so it can be saved.
        self.current_result = None

        # Build window.
        self.create_window()

        # Build interface.
        self.create_interface()

        # Start header animation.
        self.animate_header()


    # ========================================================
    # WINDOW
    # ========================================================

    def create_window(self):

        self.root = ctk.CTk()

        self.root.title(
            "Message Guard (by AI)"
        )

        self.root.geometry(
            "1100x850"
        )

        self.root.minsize(
            950,
            750
        )

        self.root.configure(
            fg_color=NAVY
        )

        # Close database and Arduino properly.
        self.root.protocol(
            "WM_DELETE_WINDOW",
            self.close
        )


    # ========================================================
    # MAIN INTERFACE
    # ========================================================

    def create_interface(self):

        # ====================================================
        # HEADER
        # ====================================================

        header = ctk.CTkFrame(
            self.root,
            fg_color="transparent"
        )

        header.pack(
            fill="x",
            padx=45,
            pady=(25, 5)
        )


        ctk.CTkLabel(
            header,
            text="🛡️",
            font=("Arial", 40)
        ).pack(
            side="left",
            padx=(0, 12)
        )


        title_frame = ctk.CTkFrame(
            header,
            fg_color="transparent"
        )

        title_frame.pack(
            side="left"
        )


        self.title_label = ctk.CTkLabel(
            title_frame,
            text="MESSAGE GUARD",
            font=("Arial", 28, "bold"),
            text_color=WHITE
        )

        self.title_label.pack(
            anchor="w"
        )


        ctk.CTkLabel(
            title_frame,
            text="by AI",
            font=("Arial", 11, "bold"),
            text_color=GOLD
        ).pack(
            anchor="w"
        )


        ctk.CTkLabel(
            header,
            text="Smarter Detection, Safer Decisions.",
            font=("Arial", 12),
            text_color=GOLD_LIGHT
        ).pack(
            side="right",
            pady=12
        )


        # ====================================================
        # GOLD DIVIDER
        # ====================================================

        ctk.CTkFrame(
            self.root,
            height=2,
            fg_color=GOLD
        ).pack(
            fill="x",
            padx=45,
            pady=(5, 15)
        )


        # ====================================================
        # MESSAGE INPUT CARD
        # ====================================================

        input_card = ctk.CTkFrame(
            self.root,
            fg_color=WHITE,
            corner_radius=18
        )

        input_card.pack(
            fill="x",
            padx=45
        )


        ctk.CTkLabel(
            input_card,
            text="💬  Analyze a Message",
            font=("Arial", 17, "bold"),
            text_color=NAVY
        ).pack(
            anchor="w",
            padx=25,
            pady=(18, 3)
        )


        ctk.CTkLabel(
            input_card,
            text=(
                "Paste or type a message to perform "
                "a security analysis."
            ),
            font=("Arial", 11),
            text_color="#617286"
        ).pack(
            anchor="w",
            padx=25
        )


        self.message_box = ctk.CTkTextbox(
            input_card,
            height=120,
            corner_radius=12,
            font=("Arial", 12),
            fg_color=NAVY_INPUT,
            text_color=WHITE,
            border_width=1,
            border_color=GOLD
        )

        self.message_box.pack(
            fill="x",
            padx=25,
            pady=12
        )


        # ====================================================
        # BUTTON AREA
        # ====================================================

        button_frame = ctk.CTkFrame(
            input_card,
            fg_color="transparent"
        )

        button_frame.pack(
            pady=(0, 18)
        )


        # Scan button.
        self.scan_button = ctk.CTkButton(
            button_frame,
            text="🔍  SCAN MESSAGE",
            width=180,
            height=42,
            corner_radius=10,
            font=("Arial", 12, "bold"),
            fg_color=GOLD,
            hover_color=GOLD_LIGHT,
            text_color=NAVY,
            command=self.start_scan
        )

        self.scan_button.grid(
            row=0,
            column=0,
            padx=5
        )


        # Clear button.
        ctk.CTkButton(
            button_frame,
            text="🗑️  CLEAR",
            width=110,
            height=42,
            corner_radius=10,
            fg_color=NAVY,
            hover_color=NAVY_LIGHT,
            command=self.clear
        ).grid(
            row=0,
            column=1,
            padx=5
        )


        # Save button.
        self.save_button = ctk.CTkButton(
            button_frame,
            text="💾  SAVE RESULT",
            width=145,
            height=42,
            corner_radius=10,
            fg_color=NAVY,
            hover_color=NAVY_LIGHT,
            command=self.save_current_result,
            state="disabled"
        )

        self.save_button.grid(
            row=0,
            column=2,
            padx=5
        )


        # History button.
        ctk.CTkButton(
            button_frame,
            text="📂  HISTORY",
            width=120,
            height=42,
            corner_radius=10,
            fg_color=NAVY,
            hover_color=NAVY_LIGHT,
            command=self.show_history
        ).grid(
            row=0,
            column=3,
            padx=5
        )


        # Analytics button.
        ctk.CTkButton(
            button_frame,
            text="📊  ANALYTICS",
            width=130,
            height=42,
            corner_radius=10,
            fg_color=NAVY,
            hover_color=NAVY_LIGHT,
            command=self.show_analytics
        ).grid(
            row=0,
            column=4,
            padx=5
        )


        # ====================================================
        # RESULT CARD
        # ====================================================

        self.result_card = ctk.CTkFrame(
            self.root,
            fg_color=NAVY_CARD,
            corner_radius=18,
            border_width=1,
            border_color=GOLD
        )

        self.result_card.pack(
            fill="x",
            padx=45,
            pady=16
        )


        # Risk emoji.
        self.result_icon = ctk.CTkLabel(
            self.result_card,
            text="🔍",
            font=("Arial", 42)
        )

        self.result_icon.pack(
            pady=(15, 0)
        )


        # Risk title.
        self.result_title = ctk.CTkLabel(
            self.result_card,
            text="WAITING",
            font=("Arial", 25, "bold"),
            text_color=WHITE
        )

        self.result_title.pack(
            pady=(2, 10)
        )


        # Visual risk meter.
        self.risk_bar = ctk.CTkProgressBar(
            self.result_card,
            width=500,
            height=10,
            corner_radius=5,
            progress_color=GOLD
        )

        self.risk_bar.set(0)

        self.risk_bar.pack(
            pady=(0, 15)
        )


        # ====================================================
        # WHY SECTION
        # ====================================================

        ctk.CTkLabel(
            self.result_card,
            text="WHY?",
            font=("Arial", 12, "bold"),
            text_color=GOLD
        ).pack(
            anchor="w",
            padx=30
        )


        self.why_text = ctk.CTkLabel(
            self.result_card,
            text="Enter a message to begin analysis.",
            font=("Arial", 11),
            text_color=WHITE,
            wraplength=850,
            justify="left"
        )

        self.why_text.pack(
            anchor="w",
            padx=30,
            pady=(4, 10)
        )


        # ====================================================
        # SUGGESTION SECTION
        # ====================================================

        ctk.CTkLabel(
            self.result_card,
            text="💡 SUGGESTION",
            font=("Arial", 12, "bold"),
            text_color=GOLD
        ).pack(
            anchor="w",
            padx=30
        )


        self.suggestion_text = ctk.CTkLabel(
            self.result_card,
            text=(
                "Your safety recommendation will "
                "appear here."
            ),
            font=("Arial", 11),
            text_color=WHITE,
            wraplength=850,
            justify="left"
        )

        self.suggestion_text.pack(
            anchor="w",
            padx=30,
            pady=(4, 15)
        )


        # ====================================================
        # FOOTER
        # ====================================================

        ctk.CTkLabel(
            self.root,
            text=(
                "🤖 AI assists the user  •  "
                "Final decision remains with the user"
            ),
            font=("Arial", 10),
            text_color=MUTED
        ).pack(
            pady=(0, 10)
        )


    # ========================================================
    # START SCAN
    # ========================================================

    def start_scan(self):

        message = self.message_box.get(
            "1.0",
            "end"
        ).strip()


        if not message:

            messagebox.showwarning(
                "Message Guard",
                "Please enter a message first."
            )

            return


        # Disable the button while scanning.
        self.scan_button.configure(
            state="disabled",
            text="⏳  ANALYZING..."
        )


        self.save_button.configure(
            state="disabled"
        )


        self.result_icon.configure(
            text="🔎"
        )


        self.result_title.configure(
            text="ANALYZING...",
            text_color=GOLD
        )


        self.why_text.configure(
            text="Checking message warning signs..."
        )


        self.suggestion_text.configure(
            text="Analyzing URLs and message patterns..."
        )


        # A thread prevents the interface from freezing.
        worker = threading.Thread(
            target=self.execute_scan,
            args=(message,),
            daemon=True
        )

        worker.start()


    # ========================================================
    # EXECUTE SCAN
    # ========================================================

    def execute_scan(self, message):

        result = self.analyzer.analyze(
            message
        )


        # ----------------------------------------------------
        # OPTIONAL ONLINE URL CHECK
        # ----------------------------------------------------

        for index, url in enumerate(
            result["urls"]
        ):

            online_result = (
                self.url_analyzer.virus_total_check(
                    url
                )
            )


            if online_result:

                result["url_results"][index] = (
                    online_result
                )


                # A malicious URL immediately raises
                # the overall result to HIGH.
                if online_result == "MALICIOUS URL":

                    result["result"] = "HIGH"


                elif (
                    online_result == "SUSPICIOUS URL"
                    and result["result"] == "LOW"
                ):

                    result["result"] = "SUSPICIOUS"


        # Return result to the GUI safely.
        self.root.after(
            0,
            lambda: self.display_result(
                result,
                message
            )
        )


    # ========================================================
    # DISPLAY RESULT
    # ========================================================

    def display_result(
        self,
        result,
        message
    ):

        # Keep latest scan available for SAVE RESULT.
        self.current_result = (
            result,
            message
        )


        status = result["result"]


        # ====================================================
        # HIGH
        # ====================================================

        if status == "HIGH":

            icon = "🔴"

            title = "HIGH RISK"

            color = RED

            progress = 1.0

            # Tell Arduino to activate red LED and buzzer.
            self.arduino.send(
                "HIGH"
            )


        # ====================================================
        # SUSPICIOUS
        # ====================================================

        elif status == "SUSPICIOUS":

            icon = "🟡"

            title = "SUSPICIOUS"

            color = YELLOW

            progress = 0.55

            # Tell Arduino to activate yellow LED.
            self.arduino.send(
                "SUSPICIOUS"
            )


        # ====================================================
        # LOW
        # ====================================================

        else:

            icon = "🟢"

            title = "LOW RISK"

            color = GREEN

            progress = 0.15

            # Tell Arduino to activate green LED.
            self.arduino.send(
                "LOW"
            )


        # ====================================================
        # UPDATE GUI
        # ====================================================

        self.result_icon.configure(
            text=icon
        )


        # Risk title gets the SAME color as its emoji.
        self.result_title.configure(
            text=title,
            text_color=color
        )


        # Risk bar gets the SAME color as the result.
        self.risk_bar.configure(
            progress_color=color
        )


        self.why_text.configure(
            text=result["why"]
        )


        suggestion = result["suggestion"]


        # Display warning words if detected.
        if result["detected"]:

            suggestion += (
                "\n\n⚠️ Warning signs: "
                + ", ".join(
                    result["detected"]
                )
            )


        # Display URL analysis if URLs exist.
        if result["urls"]:

            suggestion += (
                "\n\n🔗 URL check: "
                + ", ".join(
                    result["url_results"]
                )
            )


        self.suggestion_text.configure(
            text=suggestion
        )


        # Animate the risk meter.
        self.animate_progress(
            progress
        )


        # The user can now save this scan.
        self.save_button.configure(
            state="normal"
        )


        self.scan_button.configure(
            state="normal",
            text="🔍  SCAN MESSAGE"
        )


    # ========================================================
    # RISK BAR ANIMATION
    # ========================================================

    def animate_progress(
        self,
        target,
        current=0
    ):

        if current >= target:

            self.risk_bar.set(
                target
            )

            return


        current += 0.05


        if current > target:

            current = target


        self.risk_bar.set(
            current
        )


        self.root.after(
            25,
            lambda: self.animate_progress(
                target,
                current
            )
        )


    # ========================================================
    # SAVE CURRENT RESULT
    # ========================================================

    def save_current_result(self):

        if not self.current_result:

            return


        result, message = (
            self.current_result
        )


        # Encrypt the message before putting it into SQLite.
        encrypted_message = (
            self.encryption.encrypt(
                message
            )
        )


        detected_words = ", ".join(
            result["detected"]
        )


        url_results = ", ".join(
            result["url_results"]
        )


        # Permanently save the scan.
        self.database.save_scan(

            encrypted_message,

            result["result"],

            result["why"],

            result["suggestion"],

            detected_words,

            url_results
        )


        messagebox.showinfo(
            "Message Guard",
            "✅ Scan result permanently saved!"
        )


        self.save_button.configure(
            state="disabled"
        )


    # ========================================================
    # HISTORY WINDOW
    # ========================================================

    def show_history(self):

        history = ctk.CTkToplevel(
            self.root
        )

        history.title(
            "Message Guard - Saved History"
        )

        history.geometry(
            "900x700"
        )

        history.configure(
            fg_color=NAVY
        )


        # ====================================================
        # HISTORY TITLE
        # ====================================================

        ctk.CTkLabel(
            history,
            text="📂 SAVED SCAN HISTORY",
            font=("Arial", 23, "bold"),
            text_color=GOLD
        ).pack(
            pady=(20, 5)
        )


        ctk.CTkLabel(
            history,
            text=(
                "Your saved scans are stored permanently "
                "in the local database."
            ),
            font=("Arial", 10),
            text_color=MUTED
        ).pack(
            pady=(0, 15)
        )


        # ====================================================
        # SEARCH BAR
        # ====================================================

        search_box = ctk.CTkEntry(
            history,
            placeholder_text="🔍 Search saved history...",
            width=500,
            height=38
        )

        search_box.pack(
            pady=(0, 10)
        )


        # ====================================================
        # SCROLLABLE HISTORY AREA
        # ====================================================

        scroll = ctk.CTkScrollableFrame(
            history,
            fg_color=NAVY_CARD
        )

        scroll.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=(0, 10)
        )


        # ====================================================
        # LOAD / REFRESH HISTORY
        # ====================================================
        #
        # IMPORTANT:
        # This function reads the database AGAIN.
        #
        # Therefore, clicking REFRESH HISTORY displays
        # newly saved records without reopening the window.
        # ====================================================

        def load_history():

            # Remove the old cards first.
            for widget in scroll.winfo_children():

                widget.destroy()


            # Read the latest data from SQLite.
            records = (
                self.database.get_scans()
            )


            search = (
                search_box.get()
                .strip()
                .lower()
            )
 

            if not records:

                ctk.CTkLabel(
                    scroll,
                    text=(
                        "📭 No saved scans yet.\n\n"
                        "Scan a message and click "
                        "SAVE RESULT."
                    ),
                    font=("Arial", 13),
                    text_color=MUTED
                ).pack(
                    pady=80
                )

                return


            shown_records = 0


            for record in records:

                (
                    scan_id,
                    encrypted_message,
                    result,
                    why,
                    suggestion,
                    detected,
                    urls,
                    timestamp
                ) = record


                # Decrypt only for display/search.
                message = (
                    self.encryption.decrypt(
                        encrypted_message
                    )
                )


                searchable = (
                    message
                    + " "
                    + result
                    + " "
                    + detected
                    + " "
                    + timestamp
                ).lower()


                # Skip records that don't match search.
                if search and search not in searchable:

                    continue


                shown_records += 1


                # =================================================
                # CHOOSE RISK COLOR
                # =================================================

                if result == "HIGH":

                    color = RED

                    icon = "🔴"

                    display_result = "HIGH RISK"


                elif result == "SUSPICIOUS":

                    color = YELLOW

                    icon = "🟡"

                    display_result = "SUSPICIOUS"


                else:

                    color = GREEN

                    icon = "🟢"

                    display_result = "LOW RISK"


                # =================================================
                # HISTORY CARD
                # =================================================

                card = ctk.CTkFrame(
                    scroll,
                    fg_color=NAVY_LIGHT,
                    corner_radius=12
                )

                card.pack(
                    fill="x",
                    padx=8,
                    pady=7
                )


                ctk.CTkLabel(
                    card,
                    text=(
                        icon
                        + " "
                        + display_result
                    ),
                    font=("Arial", 14, "bold"),
                    text_color=color
                ).pack(
                    anchor="w",
                    padx=15,
                    pady=(10, 2)
                )


                # Create a short preview instead of
                # displaying the entire message.
                preview = message.replace(
                    "\n",
                    " "
                )


                if len(preview) > 110:

                    preview = (
                        preview[:110]
                        + "..."
                    )


                ctk.CTkLabel(
                    card,
                    text=preview,
                    font=("Arial", 10),
                    text_color=WHITE,
                    wraplength=700,
                    justify="left"
                ).pack(
                    anchor="w",
                    padx=15
                )


                ctk.CTkLabel(
                    card,
                    text="🕐 " + timestamp,
                    font=("Arial", 9),
                    text_color=MUTED
                ).pack(
                    anchor="w",
                    padx=15
                )


                # =================================================
                # CARD BUTTONS
                # =================================================

                card_buttons = ctk.CTkFrame(
                    card,
                    fg_color="transparent"
                )

                card_buttons.pack(
                    pady=8
                )


                ctk.CTkButton(
                    card_buttons,
                    text="👁️ VIEW",
                    width=100,
                    height=30,
                    fg_color=GOLD,
                    hover_color=GOLD_LIGHT,
                    text_color=NAVY,
                    command=lambda r=record:
                    self.view_saved_record(r)
                ).pack(
                    side="left",
                    padx=5
                )


                ctk.CTkButton(
                    card_buttons,
                    text="🗑️ DELETE",
                    width=100,
                    height=30,
                    fg_color=RED,
                    hover_color=RED_LIGHT,
                    command=lambda i=scan_id:
                    self.delete_saved_record(
                        i,
                        load_history
                    )
                ).pack(
                    side="left",
                    padx=5
                )


            # =================================================
            # NO SEARCH RESULTS
            # =================================================

            if shown_records == 0:

                ctk.CTkLabel(
                    scroll,
                    text=(
                        "🔎 No matching saved scans found."
                    ),
                    font=("Arial", 13),
                    text_color=MUTED
                ).pack(
                    pady=80
                )


        # ====================================================
        # REFRESH HISTORY BUTTON
        # ====================================================
        #
        # This is the NEW feature you asked for.
        #
        # It reloads the database without closing the
        # History window.
        # ====================================================

        ctk.CTkButton(
            history,
            text="🔄  REFRESH HISTORY",
            width=190,
            height=38,
            corner_radius=10,
            fg_color=GOLD,
            hover_color=GOLD_LIGHT,
            text_color=NAVY,
            font=("Arial", 11, "bold"),
            command=load_history
        ).pack(
            pady=(0, 8)
        )


        # ====================================================
        # SEARCH BUTTON
        # ====================================================

        ctk.CTkButton(
            history,
            text="🔍  SEARCH",
            width=130,
            height=34,
            fg_color=NAVY_LIGHT,
            hover_color="#163A60",
            command=load_history
        ).pack(
            pady=(0, 8)
        )


        # ====================================================
        # CLEAR ALL HISTORY
        # ====================================================

        ctk.CTkButton(
            history,
            text="🧹  CLEAR ALL HISTORY",
            width=190,
            height=34,
            fg_color=RED,
            hover_color=RED_LIGHT,
            command=lambda: self.clear_history(
                load_history
            )
        ).pack(
            pady=(0, 15)
        )


        # Load history immediately when window opens.
        load_history()


    # ========================================================
    # VIEW SAVED RECORD
    # ========================================================

    def view_saved_record(
        self,
        record
    ):

        (
            scan_id,
            encrypted_message,
            result,
            why,
            suggestion,
            detected,
            urls,
            timestamp
        ) = record


        # Decrypt the message only when the user chooses VIEW.
        message = (
            self.encryption.decrypt(
                encrypted_message
            )
        )


        if result == "HIGH":

            icon = "🔴"

            color = RED

            title = "HIGH RISK"


        elif result == "SUSPICIOUS":

            icon = "🟡"

            color = YELLOW

            title = "SUSPICIOUS"


        else:

            icon = "🟢"

            color = GREEN

            title = "LOW RISK"


        window = ctk.CTkToplevel(
            self.root
        )

        window.title(
            "Saved Scan Details"
        )

        window.geometry(
            "700x620"
        )

        window.configure(
            fg_color=NAVY
        )


        ctk.CTkLabel(
            window,
            text=icon + " " + title,
            font=("Arial", 25, "bold"),
            text_color=color
        ).pack(
            pady=20
        )


        text = ctk.CTkTextbox(
            window,
            width=620,
            height=470,
            font=("Arial", 12),
            fg_color=NAVY_INPUT,
            text_color=WHITE
        )

        text.pack(
            padx=30,
            pady=10
        )


        details = (
            "MESSAGE\n"
            "────────────────────────\n"
            + message
            + "\n\n"
            "WHY?\n"
            "────────────────────────\n"
            + why
            + "\n\n"
            "SUGGESTION\n"
            "────────────────────────\n"
            + suggestion
            + "\n\n"
            "WARNING SIGNS\n"
            "────────────────────────\n"
            + (
                detected
                if detected
                else "None detected"
            )
            + "\n\n"
            "URL RESULTS\n"
            "────────────────────────\n"
            + (
                urls
                if urls
                else "No URLs detected"
            )
            + "\n\n"
            "DATE & TIME\n"
            "────────────────────────\n"
            + timestamp
        )


        text.insert(
            "1.0",
            details
        )


        # Make the saved information read-only.
        text.configure(
            state="disabled"
        )


    # ========================================================
    # DELETE ONE SAVED RECORD
    # ========================================================

    def delete_saved_record(
        self,
        scan_id,
        refresh
    ):

        answer = messagebox.askyesno(
            "Delete Scan",
            "Are you sure you want to delete this scan?"
        )


        if answer:

            self.database.delete_scan(
                scan_id
            )

            # Refresh the history after deletion.
            refresh()


    # ========================================================
    # CLEAR ALL HISTORY
    # ========================================================

    def clear_history(
        self,
        refresh
    ):

        answer = messagebox.askyesno(
            "Clear History",
            "Delete ALL saved scan results?"
        )


        if answer:

            self.database.delete_all()

            # Refresh the display.
            refresh()


    # ========================================================
    # CLEAR CURRENT MESSAGE
    # ========================================================

    def clear(self):

        self.message_box.delete(
            "1.0",
            "end"
        )


        self.current_result = None


        self.result_icon.configure(
            text="🔍"
        )


        self.result_title.configure(
            text="WAITING",
            text_color=WHITE
        )


        self.risk_bar.configure(
            progress_color=GOLD
        )


        self.risk_bar.set(
            0
        )


        self.why_text.configure(
            text="Enter a message to begin analysis."
        )


        self.suggestion_text.configure(
            text=(
                "Your safety recommendation will "
                "appear here."
            )
        )


        self.save_button.configure(
            state="disabled"
        )


    # ========================================================
    # ANALYTICS
    # ========================================================

    def show_analytics(self):

        statistics = (
            self.database.get_statistics()
        )


        if not statistics:

            messagebox.showinfo(
                "Analytics",
                "No saved scans are available yet."
            )

            return


        labels = []

        values = []


        for result, count in statistics:

            if result == "HIGH":

                labels.append(
                    "🔴 High Risk"
                )

            elif result == "SUSPICIOUS":

                labels.append(
                    "🟡 Suspicious"
                )

            else:

                labels.append(
                    "🟢 Low Risk"
                )


            values.append(
                count
            )


        window = ctk.CTkToplevel(
            self.root
        )

        window.title(
            "Message Guard Analytics"
        )

        window.geometry(
            "750x600"
        )

        window.configure(
            fg_color=NAVY
        )


        ctk.CTkLabel(
            window,
            text="📊 SECURITY ANALYTICS",
            font=("Arial", 23, "bold"),
            text_color=GOLD
        ).pack(
            pady=20
        )


        fig, ax = plt.subplots(
            figsize=(7, 4),
            dpi=100
        )


        fig.patch.set_facecolor(
            NAVY
        )


        ax.set_facecolor(
            NAVY
        )


        ax.pie(
            values,
            labels=labels,
            autopct="%1.1f%%",
            textprops={
                "color": "white"
            }
        )


        ax.set_title(
            "Saved Message Classification",
            color="white"
        )


        canvas = FigureCanvasTkAgg(
            fig,
            master=window
        )


        canvas.draw()


        canvas.get_tk_widget().pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )


    # ========================================================
    # HEADER ANIMATION
    # ========================================================

    def animate_header(self):

        current = self.title_label.cget(
            "text_color"
        )


        if current == WHITE:

            self.title_label.configure(
                text_color=GOLD_LIGHT
            )

        else:

            self.title_label.configure(
                text_color=WHITE
            )


        # Repeat animation every 1.2 seconds.
        self.root.after(
            1200,
            self.animate_header
        )


    # ========================================================
    # CLOSE APPLICATION
    # ========================================================

    def close(self):

        # Close Arduino connection.
        self.arduino.close()

        # Close SQLite connection.
        self.database.close()

        # Close GUI.
        self.root.destroy()


# ============================================================
# 12. START APPLICATION
# ============================================================

if __name__ == "__main__":

    app = MessageGuardApp()

    app.root.mainloop()