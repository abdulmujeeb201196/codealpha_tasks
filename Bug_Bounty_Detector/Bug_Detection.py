from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re

app = Flask(__name__)
CORS(app)  # Allow React/Tkinter frontend to communicate with Flask

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Security patterns for multiple languages
SECURITY_PATTERNS = {
    "Python": {
        "SQL Injection": r"(SELECT|INSERT|UPDATE|DELETE).*?['\"].*?['\"]",
        "Hardcoded Passwords": r"(password\s*=\s*['\"].*?['\"])",
        "Deprecated Functions": r"\b(exec|eval|pickle\.loads|input)\b",
    },
    "Java": {
        "SQL Injection": r"PreparedStatement\s*\.\s*execute\(",
        "Hardcoded Passwords": r"(\bpassword\b\s*=\s*\".*\")",
        "Unsafe File Access": r"(FileReader|FileWriter|BufferedReader)\s*\(",
    },
    "C#": {
        "SQL Injection": r"(\bSqlCommand\b\s*\(\s*\"SELECT)",
        "Hardcoded Passwords": r"(string\s+\w+\s*=\s*\".*\")",
        "Unsafe File Access": r"(File\.Open|File\.ReadAllText|File\.WriteAllText)\(",
    },
    "JavaScript": {
        "SQL Injection": r"(\bquery\s*\(\s*\"SELECT)",
        "Eval Usage (Security Risk)": r"\beval\s*\(",
        "Insecure Local Storage": r"(localStorage\.setItem)",
    },
}

@app.route("/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    filename = file.filename
    file_ext = filename.split(".")[-1]

    # Determine language based on file extension
    language_map = {"py": "Python", "java": "Java", "cs": "C#", "js": "JavaScript"}
    language = language_map.get(file_ext, None)

    if not language or language not in SECURITY_PATTERNS:
        return jsonify({"error": "Unsupported file type"}), 400

    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)

    results = []
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Check for security vulnerabilities
    for line_num, line in enumerate(lines, start=1):
        for issue, pattern in SECURITY_PATTERNS[language].items():
            if re.search(pattern, line, re.IGNORECASE):
                results.append({"issue": issue, "line": line.strip(), "line_number": line_num})

    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
