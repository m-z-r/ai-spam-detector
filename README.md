# AI-Assisted Spam Detector

**Smarter Detection, Safer Decisions.**

Message Guard is a Python-based security application that analyzes messages for potential spam, scam indicators, and suspicious URLs. It provides risk classifications, safety recommendations, encrypted scan history, analytics, and optional Arduino hardware alerts.

## ✨ Features

- **Message Analysis:** Detects suspicious keywords and phrases associated with scams.
- **Risk Classification:** Categorizes messages as HIGH, SUSPICIOUS, or LOW risk.
- **URL Analysis:** Extracts links and checks for suspicious domain patterns.
- **VirusTotal Integration:** Optionally checks URLs using the VirusTotal API.
- **Graphical Interface:** Provides an interactive desktop application built with CustomTkinter.
- **Encrypted History:** Encrypts message content before saving scans to a local SQLite database.
- **Search and History:** View, search, refresh, and delete saved scan records.
- **Analytics Dashboard:** Visualizes saved scan statistics using Matplotlib.
- **Arduino Integration:** Sends risk results to an Arduino for LED, buzzer, and LCD alerts.

## ⚙️ How the Code Works

### 1. Message Analysis

The program converts the message to lowercase and checks it against a predefined list of suspicious words and phrases, such as `urgent`, `verify account`, `password`, and `payment required`.

Each matching phrase adds one point to the risk score.

### 2. URL Detection

The URL analyzer extracts web links from the message and checks their domains against predefined suspicious patterns.

- Suspicious URL patterns add three points to the risk score.
- If VirusTotal is configured, its results can further influence the final classification.

### 3. Risk Classification

The message receives a risk category based on its total score:

| Score | Classification |
|---|---|
| 5 or more | HIGH |
| 2–4 | SUSPICIOUS |
| 0–1 | LOW |

The application also displays an explanation and a safety recommendation.

### 4. Graphical User Interface

CustomTkinter provides the desktop interface, including:

- Message input area
- Scan and clear buttons
- Risk indicator and progress bar
- Explanation and safety recommendations
- Save result, history, and analytics controls

Background threading allows the message analysis process to run without unnecessarily freezing the interface.

### 5. Database and Encryption

SQLite stores scan results in a local database named `message_guard.db`.

Before a scan is saved, the original message is encrypted using Fernet. The database also stores the classification, explanation, recommendation, detected keywords, URL results, and timestamp.

The encryption key is derived from the local Windows username and a fixed application string. This is a simple local-storage approach, not a complete key-management system.

### 6. Arduino Communication

The application uses PySerial to communicate with an Arduino over a configured serial port.

It sends one of three text commands:

- `HIGH`
- `SUSPICIOUS`
- `LOW`

The Arduino can use these commands to control connected LEDs, a buzzer, and an LCD, depending on its firmware and wiring.

### 7. Analytics

The analytics feature retrieves saved scan counts from SQLite and displays a chart using Matplotlib. This helps visualize the distribution of recorded risk classifications.

## 🛠️ Technologies Used

- Python 3
- CustomTkinter and Tkinter
- SQLite
- Regular expressions
- Fernet encryption
- Requests
- PySerial
- Matplotlib

## 📋 Installation

### Requirements

- Python 3
- Arduino and compatible hardware, if using hardware alerts
- Internet access for optional VirusTotal URL checks

### Install Dependencies

```bash
pip install customtkinter pyserial requests cryptography matplotlib
```

The `math`, `os`, `re`, `sqlite3`, `threading`, `time`, `base64`, `hashlib`, `datetime`, `urllib.parse`, and `tkinter` modules are part of Python's standard library or Python installation.

### Run the Application

Save the Python script as `message_guard.py`, then execute:

```bash
python message_guard.py
```

Change the filename in the command if your script has a different name.

## 🔌 Configuration

### Arduino

Update the `ARDUINO_PORT` variable to match the serial port shown in the Arduino IDE. The baud rate must match the Arduino firmware.

```python
ARDUINO_PORT = "COM3"
BAUD_RATE = 9600
```

The application can still perform message analysis if the Arduino is unavailable.

### VirusTotal

Online URL checking is optional. Add your API key to `VIRUSTOTAL_API_KEY` to enable it.

**Never commit a private API key to a public repository.** Use an environment variable or another secure configuration method instead.

## ⚠️ Important Limitations

- The current detector uses predefined keywords, URL patterns, and a rule-based scoring system; it does not implement a trained machine-learning model.
- A message classified as LOW risk is not guaranteed to be safe.
- URL pattern checks are basic and cannot establish whether a website is genuinely trustworthy.
- VirusTotal results depend on API availability and the service's analysis.
- The encryption key derivation should be strengthened before relying on this application for sensitive information.

Always verify suspicious messages through trusted channels before clicking links, sharing sensitive information, or sending money.

## 📄 License

Add a `LICENSE` file if you intend to publish the project with explicit reuse permissions.

---

**Built with Python to support safer digital communication.**
