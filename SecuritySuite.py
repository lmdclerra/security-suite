"""
Security Suite
A multi-function security toolkit integrating:

1. Password Strength Assessment — Checks password strength against set rules
2. Password Generator + Hashing — Generates strong passwords and hashes them
3. Input Validation & Sanitization — Validates and cleans form inputs
4. Network Port Scanner — Scans ports to detect open/closed status
5. Network Traffic Analyzer — Captures traffic and summarizes top ports/IPs

Course: BSIT-A3103
Member: Dela Cruz, Lerra Mae
"""
# ==================== IMPORTS ====================
from tkinter import ttk, messagebox, scrolledtext, filedialog
from datetime import datetime
import tkinter as tk
import hashlib
import secrets
import string
import re
import html
import socket
import threading
import sys
import csv
import json


# ==================== IMPORT SCAPY FOR NETWORK TRAFFIC ANALYSIS ====================
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ==================== CONSTANTS ====================

COMMON_PASSWORDS = ["password", "123456", "qwerty", "admin", "letmein", "welcome"]
DICTIONARY_WORDS = ["apple", "computer", "dragon", "monkey"]

SQL_KEYWORDS = ['SELECT', 'DROP', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER']

COMMON_SERVICES = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}
# ==================== PASSWORD STRENGTH ASSESSMENT MODULE ====================
class PasswordStrengthAssessment:
    """
    Password Strength Assessment module.

    Purpose:
        Evaluates the security strength of a password using common password rules.

    Main responsibilities:
        - Check password length
        - Check uppercase, lowercase, digits, and special characters
        - Detect common weak passwords and dictionary words
        - Return a score, rating, and improvement feedback
    """    

    def evaluate_password_strength(self, password):
        """
        Analyzes password strength based on multiple security criteria.
        
        Args:
            password (str): The password to evaluate
        
        Returns:
            tuple: (score, rating, feedback_notes, checks_dict)
                - score: Numeric score out of 7
                - rating: Text rating (Weak/Moderate/Strong)
                - feedback_notes: List of improvement suggestions
                - checks_dict: Dictionary of individual check results
        """
        # Technical character requirement checks
        # Note: Length must be >= 12 for minimum requirement
        checks = {
            "length": len(password) >= 12,
            "has_upper": any(char.isupper() for char in password),
            "has_lower": any(char.islower() for char in password),
            "has_digit": any(char.isdigit() for char in password),
            "has_special": bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};':\",.<>?/\\|]", password))
        }
        
        # Blacklist checking for common weak passwords
        is_common = password.lower() in COMMON_PASSWORDS
        has_dict_word = password.lower() in DICTIONARY_WORDS
        
        # Calculate score (5 technical checks + 2 blacklist checks = 7 total)
        points = sum(checks.values())
        if not is_common:
            points += 1
        if not has_dict_word:
            points += 1
        
        # Generate feedback and determine rating
        feedback_notes = []
        
        # Force 'Weak' rating if password is blacklisted or fails most checks
        if is_common or has_dict_word or points <= 4:
            rating = "Weak"
            if is_common:
                feedback_notes.append("• Avoid commonly used passwords")
            if has_dict_word:
                feedback_notes.append("• Avoid using dictionary words")
        elif 5 <= points <= 6:
            rating = "Moderate"
        else:
            rating = "Strong"
        
        # Detailed improvement suggestions
        if not checks["length"]:
            feedback_notes.append("• Use at least 12 characters for security")
        if not checks["has_upper"]:
            feedback_notes.append("• Add uppercase letters")
        if not checks["has_lower"]:
            feedback_notes.append("• Add lowercase letters")
        if not checks["has_digit"]:
            feedback_notes.append("• Include numbers")
        if not checks["has_special"]:
            feedback_notes.append("• Include special characters")
        
        return points, rating, feedback_notes, checks


# ==================== PASSWORD GENERATION MODULE ====================
class PasswordGenerator:
    """
    Password Generator module.

    Purpose:
        Generates strong random passwords, hashes them, and saves them to file.

    Main responsibilities:
        - Generate cryptographically secure passwords
        - Hash passwords using selected algorithms
        - Save generated passwords and metadata to a text file
    """

    def generate_random_password(self, length=16):
        """
        Generate a cryptographically secure random password.
        
        Args:
            length (int): Desired password length (minimum 12, default 16)
        
        Returns:
            str: A strong random password meeting all security criteria
        """
        # Ensure minimum length for security
        length = max(length, 12)
        
        # Define character sets for password composition
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special_chars = "!@#$%^&*()_-+={}[];:,.?"
        
        # Combine all character sets
        all_chars = lowercase + uppercase + digits + special_chars
        
        # Guarantee at least one character from each required set
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special_chars)
        ]
        
        # Fill remaining positions with random characters
        password += [secrets.choice(all_chars) for _ in range(length - 4)]
        
        # Shuffle to prevent predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)


    def hash_password(self, password, algorithm='sha256'):
        """
        Generate cryptographic hash of a password using specified algorithm.
        
        Args:
            password (str): Password to hash
            algorithm (str): Hash algorithm (sha256, sha512, md5)
        
        Returns:
            str: Hexadecimal hash digest of the password
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(password.encode('utf-8'))
        return hash_obj.hexdigest()


    def save_password_to_file(self, password, hash_value, strength=None, filename="passwords.txt"):
        """
        Append generated password and metadata to secure storage file in passwords.txt.
        Each entry includes timestamp, password, and SHA-256 hash in append mode.
        
        Required format:
            Timestamp: YYYY-MM-DD HH:MM:SS
            Password: <raw password>
            Hash: <sha256 hash>
            (separator line)
        
        Args:
            password (str): The generated password
            hash_value (str): SHA-256 hash digest of the password
            strength (str): Strength rating (optional, for backward compatibility)
            filename (str): Output file path (default: passwords.txt)
        """
        # Generate timestamp when password was generated
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")        
        
        # Open file in append mode (never overwrites existing entries)
        with open(filename, 'a', encoding='utf-8') as file:
            file.write(f"Timestamp: {timestamp}\n")
            file.write(f"Password: {password}\n")
            file.write(f"Hash: {hash_value}\n")
            file.write("-" * 80 + "\n")


# ==================== INPUT VALIDATION MODULE ====================
class InputValidation:
    """
    Input Validation and Sanitization module.

    Purpose:
        Validates and sanitizes user input to reduce security risks and format errors.

    Main responsibilities:
        - Validate form fields such as full name, email, username, and message
        - Detect unsafe input patterns such as XSS and SQL injection keywords
        - Sanitize dangerous input while preserving safe content
    """

    def validate_field(self, field_name, value):
        """
        Validate user input against security and format requirements.
        Prevents XSS, SQL injection, and format violations.
        
        Args:
            field_name (str): Name of the field being validated
            value (str): User input value
        
        Returns:
            tuple: (is_valid, errors_list)
                - is_valid: Boolean indicating if input passes all checks
                - errors_list: List of specific validation error messages
        """
        errors = []
        is_valid = True
        
        if field_name == "First Name" or field_name == "Last Name":
            if not value.strip():
                errors.append("Must not be empty")
                is_valid = False

            if len(value.strip()) < 2:
                errors.append("Must be at least 2 characters")
                is_valid = False

            if re.search(r'[0-9]', value):
                errors.append("Must not contain numbers")
                is_valid = False

            if re.search(r'[^a-zA-Z\s\-\']', value):
                errors.append("Only letters, spaces, hyphens, and apostrophes allowed")
                is_valid = False
        
        elif field_name == "Email Address":
            email = value.strip()
            
            # Must contain exactly one @ symbol
            at_count = email.count("@")
            if at_count == 0:
                errors.append("Invalid email format (missing '@' symbol)")
                is_valid = False
            elif at_count > 1:
                errors.append("Invalid email format (multiple '@' symbols detected)")
                is_valid = False
            else:
                local, domain = email.split("@", 1)
                
                # No whitespace allowed
                if " " in email:
                    errors.append("Must not contain spaces")
                    is_valid = False
                
                # Local part must start with alphanumeric character
                if not local or not local[0].isalnum():
                    errors.append("Must not start with special character")
                    is_valid = False
                
                # Domain must have at least one dot and valid TLD (e.g., gmail.com, example.org)
                if not re.search(r'\.[a-zA-Z]{2,}$', domain):
                    errors.append("Invalid email format (missing domain like .com, .org)")
                    is_valid = False
                
                # Domain should have valid format
                if not re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$', domain) and len(domain) > 1:
                    errors.append("Invalid email format (invalid domain structure)")
                    is_valid = False
                
                # Prevent consecutive dots
                if ".." in email:
                    errors.append("Must not contain consecutive dots")
                    is_valid = False
                
                # Local part validation
                if local.startswith(".") or local.endswith("."):
                    errors.append("Invalid email format (local part cannot start or end with dot)")
                    is_valid = False
        
        elif field_name == "Username":
            # Length constraints for username
            if len(value) < 4 or len(value) > 16:
                errors.append("Must be between 4 and 16 characters")
                is_valid = False
            
            if " " in value:
                errors.append("Must not contain whitespace")
                is_valid = False
            
            # Only alphanumeric and underscore, cannot start with number
            if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', value):
                errors.append("Only letters, numbers, underscores allowed; cannot begin with number")
                is_valid = False
        
        elif field_name == "Message / Comment":
            # Prevent empty messages
            if not value.strip():
                errors.append("Must not be empty")
                is_valid = False
            
            # Maximum character limit
            if len(value) > 250:
                errors.append("Must not exceed 250 characters")
                is_valid = False
            
            # XSS prevention: block script tags
            if re.search(r'<script[^>]*>.*?</script>', value, re.IGNORECASE | re.DOTALL):
                errors.append("The message contains prohibited HTML tags (<script>)")
                is_valid = False
            
            # XSS prevention: block image tags with suspicious attributes
            if re.search(r'<img[^>]*>', value, re.IGNORECASE):
                errors.append("The message contains prohibited HTML tags (<img>)")
                is_valid = False
            
            # SQL injection prevention: block SQL keywords
            for keyword in SQL_KEYWORDS:
                if re.search(r'\b' + re.escape(keyword) + r'\b', value, re.IGNORECASE):
                    errors.append(f"The message contains SQL keyword '{keyword}' (SQL injection prevention)")
                    is_valid = False
                    break
        
        return is_valid, errors


    def sanitize_field(self, field_name, value):
        """
        Clean and sanitize user input by removing or escaping dangerous content.
        
        Args:
            field_name (str): Name of the field being sanitized
            value (str): User input value
        
        Returns:
            tuple: (sanitized_value, sanitization_note)
                - sanitized_value: Cleaned input string
                - sanitization_note: Description of changes made, empty if none
        """
        original = value
        sanitized = value
        note = ""
        
        if field_name == "First Name" or field_name == "Last Name":
            sanitized = re.sub(r'[<>/]', '', value)
            sanitized = re.sub(r'[^a-zA-Z\s\-\']', '', sanitized)
            sanitized = re.sub(r'\s+', ' ', sanitized).strip()

            # Capitalize each word properly (Title Case)
            sanitized = sanitized.title()

            if sanitized != original:
                note = "Formatted to proper case and removed unsafe characters"
        
        elif field_name == "Email Address":
            # Remove all whitespace
            sanitized = re.sub(r'\s+', '', value)

            # If more than one @ exists, keep only the first valid separator
            if sanitized.count("@") > 1:
                parts = sanitized.split("@")
                sanitized = parts[0] + "@" + "".join(parts[1:])
                note = "Extra '@' symbol removed"

            # Remove leading special characters
            while sanitized and sanitized[0] in '@.-_':
                sanitized = sanitized[1:]
                if not note:
                    note = "Leading special character removed"

            # HTML escape to prevent XSS
            sanitized = html.escape(sanitized)

            if sanitized != original and not note:
                note = "HTML special characters escaped"
        
        elif field_name == "Username":
            # Remove all whitespace first
            sanitized = value.replace(" ", "")

            # Keep only alphanumeric and underscores
            sanitized = re.sub(r'[^a-zA-Z0-9_]', '', sanitized)

            # Remove leading numbers
            sanitized = re.sub(r'^[0-9]+', '', sanitized)

            if sanitized != original:
                note = "Whitespace and invalid characters removed"
        
        elif field_name == "Message / Comment":
            # Remove script tags to prevent XSS
            sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
            
            # Remove image tags to prevent XSS
            sanitized = re.sub(r'<img[^>]*>', '', sanitized, flags=re.IGNORECASE)
            
            # Remove SQL keywords to prevent injection
            for keyword in SQL_KEYWORDS:
                sanitized = re.sub(r'\b' + re.escape(keyword) + r'\b', '', sanitized, flags=re.IGNORECASE)
            
            # HTML escape remaining content
            sanitized = html.escape(sanitized)
            
            # Normalize whitespace
            sanitized = re.sub(r'\s+', ' ', sanitized).strip()
            
            if sanitized != original:
                note = "Potentially dangerous content removed and escaped"
        
        return sanitized, note


# ==================== PORT SCANNER CLASS ====================
class PortScanner:
    """
    Port Scanner module.

    Purpose:
        Scans a host or IP address for open and closed network ports.

    Main responsibilities:
        - Accept flexible port input and scan presets
        - Resolve hostnames into IP addresses
        - Perform TCP-based port scanning
        - Optionally detect service banners
        - Export scan results in TXT, CSV, and JSON formats
    """
    
    def __init__(self, parent_frame):
        """Initialize the Port Scanner GUI and variables"""
        self.parent_frame = parent_frame
        self.scanning = False  # Flag to track if scanning is in progress
        self.scan_completed = False  # Flag to indicate if scan completed successfully
        self.end_time_of_scan = None  # Store end time of scan for export
        self.scan_results = []  # Store scan results for export
        self.scan_thread = None  # Track scan thread
        self.all_scan_output = []  # Store all scan output lines with their types
        
        # Create GUI elements
        self.create_widgets()
    
    def create_widgets(self):
        """Create and arrange all GUI elements"""        
        
        # Input Frame
        input_frame = tk.Frame(self.parent_frame)
        input_frame.config(bg="#ffffff", bd=1, relief=tk.SOLID)
        input_frame.pack(pady=10, padx=20, fill=tk.X)
        
        # IP/Hostname Input
        tk.Label(input_frame, text="IP Address or Hostname:", background="#ffffff", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.ip_entry = tk.Entry(
            input_frame, width=40, font=("Arial", 10), 
            relief=tk.SOLID,
            borderwidth=1
        )
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5)
        self.ip_entry.insert(0, "127.0.0.1")
        
        # Port Range Preset Dropdown
        tk.Label(input_frame, text="Scan Preset:", background="#ffffff", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.preset_var = tk.StringVar(value="Custom")
        preset_options = [
            "Custom",
            "Common Ports (Top 20)",
            "Web Servers (80, 443, 8080, 8443)",
            "Mail Servers (25, 110, 143, 465, 587, 993, 995)",
            "Database Servers (1433, 3306, 5432, 27017)",
            "Remote Access (22, 23, 3389, 5900)",
            "All Well-Known (1-1024)"
        ]
        preset_dropdown = ttk.Combobox(input_frame, textvariable=self.preset_var, values=preset_options, width=43, state="readonly")
        preset_dropdown.grid(row=1, column=1, padx=10, pady=5)
        preset_dropdown.bind("<<ComboboxSelected>>", self.apply_preset)
        
        # Port Range Input
        tk.Label(input_frame, text="Port:", background="#ffffff", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky=tk.W, pady=5)
        self.port_entry = tk.Entry(
            input_frame, width=40, font=("Arial", 10),
            relief=tk.SOLID,
            borderwidth=1
        )
        self.port_entry.grid(row=2, column=1, sticky=tk.W, padx=10, pady=5)
        self.port_entry.insert(0, "20")
        self.port_entry.bind("<KeyRelease>", self.on_manual_port_entry)

        tk.Label(
            input_frame, 
            text="Format example: single (80), range (1-100), or list (3,7 or 1-7,20-50)", 
            font=("Arial", 8, "italic"), 
            fg="#7f8c8d"
        ).grid(row=3, column=1, sticky=tk.W, padx=10, pady=2)
        
        
        # Service Detection Option
        self.detect_service_var = tk.BooleanVar(value=True)
        service_check = tk.Checkbutton(input_frame, text="Enable Service Detection (Banner Grabbing)", 
                                      variable=self.detect_service_var, font=("Arial", 10))
        service_check.grid(row=4, column=1, sticky=tk.W, padx=10, pady=5)

        s = ttk.Style()
        s.theme_use('clam')
        s.configure("green.Horizontal.TProgressbar", foreground="#27ae60", background="#27ae60")
        
        # Progress Bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            self.parent_frame, 
            variable=self.progress_var, 
            maximum=100, 
            mode='determinate',
            style="green.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(pady=5, padx=20, fill=tk.X)
        
        self.progress_status = tk.Label(self.parent_frame, text="...", font=("Arial", 10), fg="#349FA3")
        self.progress_status.pack(pady=5)        
                        
        # Button Frame
        button_frame = tk.Frame(self.parent_frame)
        button_frame.pack(pady=10)
        
        # Scan Button
        self.scan_button = tk.Button(
            button_frame, 
            text="Start Scan", 
            command=self.start_scan,
            bg="#27ae60",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2"
        )
        self.scan_button.grid(row=0, column=0, padx=5)
        
        # Stop Scan Button
        self.stop_scan_button = tk.Button(
            button_frame, 
            text="Stop Scan", 
            command=self.stop_scan,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.stop_scan_button.grid(row=0, column=1, padx=5)
        
        # Clear Button
        self.clear_button = tk.Button(
            button_frame, 
            text="Clear Results", 
            command=self.clear_results,
            bg="#3498db",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2"
        )
        self.clear_button.grid(row=0, column=2, padx=5)
        
        # Export Button
        self.export_button = tk.Button(
            button_frame, 
            text="Export Results", 
            command=self.export_results,
            bg="#9b59b6",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2"
        )
        self.export_button.grid(row=0, column=3, padx=5)
        
        # Filter Frame for Results
        filter_result_frame = tk.Frame(self.parent_frame)
        filter_result_frame.pack(pady=5, padx=20, fill=tk.X)
        
        tk.Label(filter_result_frame, text="Filter Results:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="all")
        tk.Radiobutton(filter_result_frame, text="All"          , variable=self.filter_var, value="all"   , command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_result_frame, text="Open Only"    , variable=self.filter_var, value="open"  , command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_result_frame, text="Closed Only"  , variable=self.filter_var, value="closed", command=self.apply_filter).pack(side=tk.LEFT, padx=5)        
        
        # Output Frame
        output_frame = tk.Frame(self.parent_frame)
        output_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        tk.Label(output_frame, text="Scan Results:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        # Scrolled Text Widget for Output
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            width=70,
            height=15,
            font=("Consolas", 9),
            bg="#ecf0f1",
            fg="#2c3e50",
            wrap=tk.WORD
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)

        # Configure text tags for color-coding
        self.output_text.tag_config("open_port", foreground="#27ae60", font=("Consolas", 9, "bold"))  # Green for open
        self.output_text.tag_config("closed_port", foreground="#e74c3c")  # Red for closed
        self.output_text.tag_config("service", foreground="#3498db", font=("Consolas", 9, "italic"))
        self.output_text.tag_config("warning", foreground="#f39c12", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("info", foreground="#34495e")
        self.output_text.tag_config("header", foreground="#2c3e50", font=("Consolas", 9, "bold"))
    
    def display_output(self, message, tag=None):
        """Safely display a message in the output text widget."""
        # Store output for filtering
        self.all_scan_output.append((message, tag))

        # Schedule GUI update on the main Tkinter thread
        self.parent_frame.after(0, lambda: self._display_output_gui(message, tag))


    def _display_output_gui(self, message, tag=None):
        """Update the scan results display box."""
        filter_type = self.filter_var.get()

        # Progress lines should appear live while scanning
        if message.startswith("Scanning port "):
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            if tag:
                self.output_text.insert("1.0", message, tag)
            else:
                self.output_text.insert("1.0", message)
            self.output_text.config(state=tk.DISABLED)
            return

        # Final scan results should appear only after scanning completes
        should_display = False

        if filter_type == "all":
            should_display = True
        elif filter_type == "open":
            if tag in ["open_port", "service", "warning", "header", "info"] and "CLOSED" not in message:
                should_display = True
        elif filter_type == "closed":
            if tag in ["closed_port", "header", "info"]:
                should_display = True

        if should_display and self.scan_completed:
            self.output_text.config(state=tk.NORMAL)
            if tag:
                self.output_text.insert(tk.END, message + "\n", tag)
            else:
                self.output_text.insert(tk.END, message + "\n")
            self.output_text.see(tk.END)
            self.output_text.config(state=tk.DISABLED)

    def update_scan_progress(self, progress, text):
        """Safely schedule progress updates on the main GUI thread."""
        self.parent_frame.after(0, lambda: self._update_scan_progress_gui(progress, text))


    def _update_scan_progress_gui(self, progress, text):
        """Actual GUI update for scan progress."""
        self.progress_var.set(progress)
        self.progress_status.config(text=text)
    
    def apply_filter(self):
        """Apply the selected filter to the final displayed scan results."""
        if not self.scan_completed or not self.scan_results:
            return

        open_ports = [r for r in self.scan_results if r["status"] == "OPEN"]
        closed_ports = [r for r in self.scan_results if r["status"] == "CLOSED"]
        scanned_count = len(self.scan_results)

        self.render_final_results(scanned_count, open_ports, closed_ports)
    
    def clear_results(self):
        """Clear the output text widget"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.scan_results = []
        self.all_scan_output = []
        self.scan_completed = False
        self.progress_var.set(0)
        self.progress_status.config(text="...")
        
    def ask_export_scope(self):
        """Ask user whether to export All, Open Only, or Closed Only."""
        dialog = tk.Toplevel(self.parent_frame)
        dialog.title("Select Export Scope")
        dialog.geometry("350x220")
        dialog.resizable(False, False)
        dialog.grab_set()
        dialog.transient(self.parent_frame)

        # Center the dialog on screen
        dialog.update_idletasks()
        dialog_width = dialog.winfo_width()
        dialog_height = dialog.winfo_height()
        screen_width = dialog.winfo_screenwidth()
        screen_height = dialog.winfo_screenheight()
        x_position = (screen_width - dialog_width) // 2
        y_position = (screen_height - dialog_height) // 2
        dialog.geometry(f"{dialog_width}x{dialog_height}+{x_position}+{y_position}")

        selected_scope = tk.StringVar(value="all")
        result_container = {"scope": None}

        tk.Label(dialog, text="Choose Results to Export:", font=("Arial", 12, "bold")).pack(pady=15)

        tk.Radiobutton(dialog, text="All", variable=selected_scope, value="all").pack(anchor=tk.W, padx=30, pady=5)
        tk.Radiobutton(dialog, text="Open Only", variable=selected_scope, value="open").pack(anchor=tk.W, padx=30, pady=5)
        tk.Radiobutton(dialog, text="Closed Only", variable=selected_scope, value="closed").pack(anchor=tk.W, padx=30, pady=5)

        def on_ok():
            result_container["scope"] = selected_scope.get()
            dialog.destroy()

        tk.Button(dialog, text="Proceed", command=on_ok).pack(pady=15)
        dialog.wait_window()
        return result_container["scope"]
    
    def parse_ports(self, port_input):
        ports = set()

        try:
            parts = port_input.split(",")

            for part in parts:
                part = part.strip()

                if not part:
                    raise ValueError("Port input must not be empty.")

                # Range format
                if "-" in part:
                    split_parts = part.split("-")
                    if len(split_parts) != 2:
                        raise ValueError("Invalid port range format. Use start-end, like 20-80.")

                    start_str, end_str = split_parts

                    try:
                        start = int(start_str)
                        end = int(end_str)
                    except ValueError:
                        raise ValueError("Ports must be valid whole numbers.")

                    if start < 1 or end < 1:
                        raise ValueError("Ports must be within the valid range of 1 to 65535.")

                    if start > 65535 or end > 65535:
                        raise ValueError("Ports must be within the valid range of 1 to 65535.")

                    if start > end:
                        raise ValueError("Start port cannot be greater than end port.")

                    for p in range(start, end + 1):
                        ports.add(p)

                # Single port format
                else:
                    try:
                        p = int(part)
                    except ValueError:
                        raise ValueError("Ports must be valid whole numbers.")

                    if p < 1 or p > 65535:
                        raise ValueError("Ports must be within the valid range of 1 to 65535.")

                    ports.add(p)

            return sorted(ports)

        except ValueError:
            raise
    
    def apply_preset(self, event=None):
        """Apply preset into the single port input box"""
        preset = self.preset_var.get()

        if preset == "Custom":
            self.port_entry.delete(0, tk.END)
            return

        presets = {
            "Common Ports (Top 20)": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,3306,3389,5432,5900,8080",
            "Web Servers (80, 443, 8080, 8443)": "80,443,8080,8443",
            "Mail Servers (25, 110, 143, 465, 587, 993, 995)": "25,110,143,465,587,993,995",
            "Database Servers (1433, 3306, 5432, 27017)": "1433,3306,5432,27017",
            "Remote Access (22, 23, 3389, 5900)": "22,23,3389,5900",
            "All Well-Known (1-1024)": "1-1024"
        }

        if preset in presets:
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, presets[preset])
    
    def on_manual_port_entry(self, event=None):
        """Switch preset to Custom when user types manually"""
        self.preset_var.set("Custom")
    
    def grab_banner(self, host, port, timeout=2):
        """Attempt to grab service banner for identification"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Try sending HTTP request for web services
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port in [443, 8443]:  # HTTPS
                return "HTTPS/SSL"
            else:
                # For other services, just try to receive
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Clean up banner (first line only)
            if banner:
                return banner.split('\n')[0][:70]  # Limit length
            return None
        except:
            return None
    
    def get_vulnerability_hint(self, port, service):
        """Provide security hints for common vulnerabilities"""
        hints = {
            21: "⚠ FTP - Unencrypted protocol, credentials sent in plaintext",
            23: "⚠ Telnet - Highly insecure! Use SSH (port 22) instead",
            25: "ℹ SMTP - Ensure TLS/SSL is enabled (port 587)",
            80: "⚠ HTTP - Unencrypted web traffic, consider HTTPS (port 443)",
            135: "⚠ RPC - Often targeted for exploits, ensure firewall configured",
            139: "⚠ NetBIOS - Legacy protocol, disable if not needed",
            445: "⚠ SMB - High-value target, ensure latest patches installed",
            3306: "⚠ MySQL - Database should not be publicly accessible",
            3389: "⚠ RDP - High risk for brute-force, use VPN or strong auth",
            5432: "⚠ PostgreSQL - Database should not be publicly accessible",
            5900: "⚠ VNC - Often has weak passwords, use strong authentication"
        }
        return hints.get(port, None)
    
    def get_filtered_results(self):
        """Return scan results based on the selected filter."""
        # Get the current filter selection from the radio buttons (all/open/closed)
        filter_type = self.filter_var.get()
        
        # Return matching results for export based on the selected filter
        if filter_type == "all":
            return self.scan_results
            
        elif filter_type == "open":
            return [result for result in self.scan_results if result["status"] == "OPEN"]
            
        elif filter_type == "closed":
            return [result for result in self.scan_results if result["status"] == "CLOSED"]
            
        else:
            return self.scan_results
    
    def ask_export_format(self):
        """Show dialog for selecting export format."""
        format_dialog = tk.Toplevel(self.parent_frame)
        format_dialog.title("Select Export Format")
        format_dialog.geometry("400x280")
        format_dialog.resizable(True, True)
        format_dialog.grab_set()
        format_dialog.transient(self.parent_frame)

        format_dialog.update_idletasks()
        dialog_width = format_dialog.winfo_width()
        dialog_height = format_dialog.winfo_height()
        screen_width = format_dialog.winfo_screenwidth()
        screen_height = format_dialog.winfo_screenheight()
        x_position = (screen_width - dialog_width) // 2
        y_position = (screen_height - dialog_height) // 2
        format_dialog.geometry(f"{dialog_width}x{dialog_height}+{x_position}+{y_position}")

        selected_format = tk.StringVar(value="txt")

        tk.Label(format_dialog, text="Choose Export Format:", font=("Arial", 12, "bold")).pack(pady=15)

        format_frame = tk.Frame(format_dialog)
        format_frame.pack(pady=10)

        tk.Radiobutton(format_frame, text="Text File (.txt) - Human readable format",
                    variable=selected_format, value="txt", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(format_frame, text="CSV File (.csv) - Spreadsheet compatible",
                    variable=selected_format, value="csv", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(format_frame, text="JSON File (.json) - Structured data format",
                    variable=selected_format, value="json", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)

        result_container = {'format': None}

        def on_proceed():
            result_container['format'] = selected_format.get()
            format_dialog.destroy()

        def on_cancel():
            format_dialog.destroy()

        button_frame = tk.Frame(format_dialog)
        button_frame.pack(pady=15)

        tk.Button(button_frame, text="Proceed", command=on_proceed, bg="#27ae60", fg="white",
                font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=on_cancel, bg="#e74c3c", fg="white",
                font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)

        format_dialog.wait_window()
        return result_container['format']
    
    def ask_export_file_path(self, file_format):
        """Ask user where to save the export file."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"port_scan_{timestamp}.{file_format}"

        if file_format == 'txt':
            file_types = [("Text File", "*.txt")]
            default_ext = ".txt"
        elif file_format == 'csv':
            file_types = [("CSV File", "*.csv")]
            default_ext = ".csv"
        else:
            file_types = [("JSON File", "*.json")]
            default_ext = ".json"

        return filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=file_types,
            initialfile=default_filename,
            title="Save Port Scan Results"
        )
    

    def export_scan_to_csv(self, file_path, filtered_results, filter_type):
        """Export filtered scan results to CSV with structured header."""

        export_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # ============================================
            # HEADER SECTION (like TXT/JSON)
            # ============================================
            writer.writerow(["PORT SCAN RESULTS"])
            writer.writerow(["=" * 80])

            writer.writerow([f"Export Date/Time: {export_time}"])
            writer.writerow([f"Scan Completed At: {self.end_time_of_scan}"])
            writer.writerow([f"Filter Applied: {filter_type.upper()}"])

            writer.writerow([f"Total Ports Scanned: {len(self.scan_results)}"])
            writer.writerow([f"Exported Ports: {len(filtered_results)}"])

            open_count = sum(1 for r in self.scan_results if r["status"] == "OPEN")
            closed_count = sum(1 for r in self.scan_results if r["status"] == "CLOSED")

            writer.writerow([f"Open Ports (Total): {open_count}"])
            writer.writerow([f"Closed Ports (Total): {closed_count}"])

            writer.writerow(["=" * 80])
            writer.writerow([])  # empty line

            # ============================================
            # TABLE HEADER
            # ============================================
            writer.writerow(['Timestamp', 'Port', 'Status', 'Service', 'Security Note'])

            # ============================================
            # DATA ROWS
            # ============================================
            for result in filtered_results:
                writer.writerow([
                    result["timestamp"],
                    result["port"],
                    result["status"],
                    result["service"],
                    result["security_note"]
                ])

            # ============================================
            # FOOTER
            # ============================================
            writer.writerow([])
            writer.writerow([f"--- Scan completed at [{self.end_time_of_scan}] ---"])


    def export_scan_to_json(self, file_path, filtered_results, filter_type, export_time):
        """Export filtered scan results to JSON."""
        with open(file_path, 'w', encoding='utf-8') as f:
            export_data = {
                'scan_info': {
                    'export_time': export_time,
                    'scan_completed_at': self.end_time_of_scan,
                    'filter_applied': filter_type.upper(),
                    'total_ports_scanned': len(self.scan_results),
                    'exported_ports': len(filtered_results),
                    'open_ports': sum(1 for r in self.scan_results if r["status"] == 'OPEN'),
                    'closed_ports': sum(1 for r in self.scan_results if r["status"] == 'CLOSED')
                },
                'results': [
                    {
                        'timestamp': r["timestamp"],
                        'port': r["port"],
                        'status': r["status"],
                        'service': r["service"],
                        'security_note': r["security_note"]
                    } for r in filtered_results
                ]
            }
            json.dump(export_data, f, indent=2)      

    def export_scan_to_txt(self, file_path, filtered_results, filter_type, export_time):
        """Export filtered scan results to TXT."""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("PORT SCAN RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Export Date/Time: {export_time}\n")
            f.write(f"Filter Applied: {filter_type.upper()}\n")
            f.write(f"Total Ports Scanned: {len(self.scan_results)}\n")
            f.write(f"Exported Ports: {len(filtered_results)}\n")
            f.write(f"Open Ports (Total): {sum(1 for r in self.scan_results if r['status'] == 'OPEN')}\n")
            f.write(f"Closed Ports (Total): {sum(1 for r in self.scan_results if r['status'] == 'CLOSED')}\n")
            f.write("=" * 80 + "\n\n")

            for result in filtered_results:
                f.write(f"[{result['timestamp']}] Port {result['port']}: {result['status']}\n")

                if result["service"] != "N/A":
                    f.write(f"  Service: {result['service']}\n")

                if result["security_note"] != "N/A":
                    f.write(f"  Security: {result['security_note']}\n")

                f.write("\n")

            f.write(f"--- Scan completed at [{self.end_time_of_scan}] ---\n") 

    def export_results(self):
        """Export scan results to file (respects current filter setting)."""
        if not self.scan_results:
            messagebox.showwarning("No Data", "No scan results to export. Please run a scan first.")
            return

        filter_type = self.ask_export_scope()
        if not filter_type:
            return

        # Get results based on chosen export scope
        if filter_type == "all":
            filtered_results = self.scan_results
        elif filter_type == "open":
            filtered_results = [result for result in self.scan_results if result["status"] == "OPEN"]
        elif filter_type == "closed":
            filtered_results = [result for result in self.scan_results if result["status"] == "CLOSED"]
        else:
            filtered_results = self.scan_results

        if not filtered_results:
            filter_name = {"all": "All", "open": "Open", "closed": "Closed"}.get(filter_type, filter_type)
            messagebox.showwarning("No Data", f"No {filter_name} ports to export with current filter setting.")
            return

        file_format = self.ask_export_format()
        if not file_format:
            return

        file_path = self.ask_export_file_path(file_format)
        if not file_path:
            return

        try:
            export_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if file_format == 'csv':
                self.export_scan_to_csv(file_path, filtered_results, filter_type)
            elif file_format == 'json':
                self.export_scan_to_json(file_path, filtered_results, filter_type, export_time)
            else:
                self.export_scan_to_txt(file_path, filtered_results, filter_type, export_time)

            messagebox.showinfo(
                "Success",
                f"Results exported to:\n{file_path}\n\n"
                f"Filter: {filter_type.upper()}\n"
                f"Exported: {len(filtered_results)} of {len(self.scan_results)} ports"
            )
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def validate_inputs(self, host, port_input):
        """Validate host and single flexible port input"""
        if not host or host.strip() == "":
            return False, "Error: Please enter a valid IP address or hostname.", None

        if not port_input or port_input.strip() == "":
            return False, "Error: Please enter a port or port range.", None

        try:
            port_list = self.parse_ports(port_input)
            return True, "", port_list
        except ValueError as e:
            return False, str(e), None
    
    def resolve_host(self, host):
        """
        Resolve hostname to IP address
        Returns: (success, ip_address, error_message)
        """
        try:
            ip_address = socket.gethostbyname(host)
            return True, ip_address, ""
        except socket.gaierror:
            return False, None, "Error: Unable to resolve hostname. Host unreachable or DNS failure."
        except socket.error as e:
            return False, None, f"Error: {str(e)}"
    
    def scan_port(self, host, port, timeout=0.7, detect_service=False):
        """
        Scan one TCP port on the target host.

        Uses a TCP connect scan and optionally performs banner grabbing.
        Returns whether the port is open and any detected service info.
        """
        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set timeout for faster scanning
            sock.settimeout(timeout)
            
            # Try TCP connection
            result = sock.connect_ex((host, port))
            sock.close()  # Always close socket to free system resources
            
            # Check scan result
            if result == 0:
                service_info = None
                # Open port; optionally detect service
                if detect_service:
                    service_info = self.grab_banner(host, port)
                    
                return True, service_info
            else:
                # Closed or filtered port
                return False, None
                
        except socket.error:
            # Treat network errors as inaccessible
            return False, None
    
    def perform_scan(self, host, port_list):
        """Run the full scan and store the results."""
        success, ip_address, error_msg = self.resolve_host(host)
        if not success:
            self.display_output(error_msg, "warning")
            self.enable_scan_button()
            return

        self.display_output(f"Scanning host: {host} ({ip_address})", "header")
        self.display_output(f"Ports to scan: {', '.join(map(str, port_list[:10]))}" + (" ..." if len(port_list) > 10 else ""), "info")
        self.display_output("-" * 50, "info")

        open_ports = []
        closed_ports = []
        detect_service = self.detect_service_var.get()
        total_ports = len(port_list)
                
        scanned_count = 0

        count_open = 0  
        count_closed = 0  
        
        for port in port_list:
            if not self.scanning:
                self.display_output("Scan cancelled by user.", "warning")
                break

            is_open, service_info = self.scan_port(ip_address, port, detect_service=detect_service)
            scanned_count += 1

            progress = (scanned_count / total_ports) * 100
            self.update_scan_progress(progress, f"Scanning port {port} ({scanned_count} out of {total_ports})")
            self.display_output(f"Scanning port {port} ({scanned_count} out of {total_ports})", "info")

            scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            if is_open:
                count_open += 1
                self.display_output(f"{count_open}. [{scan_time}] Port {port}: OPEN", "open_port")

                if service_info:
                    self.display_output(f"  -- Service: {service_info}", "service")

                hint = self.get_vulnerability_hint(port, service_info)
                if hint:
                    self.display_output(f"  -- {hint}", "warning")

                result_data = {
                    'timestamp': scan_time,
                    'port': port,
                    'status': "OPEN",
                    'service': service_info if service_info else "N/A",
                    'security_note': hint if hint else "N/A"
                }
                open_ports.append(result_data)
                self.scan_results.append(result_data)
                
            else:
                count_closed += 1
                result_data = {
                    'timestamp': scan_time,
                    'port': port,
                    'status': "CLOSED",
                    'service': "N/A",
                    'security_note': "N/A"
                }
                closed_ports.append(result_data)
                self.scan_results.append(result_data)
                self.display_output(f"{count_closed}. [{scan_time}] Port {port}: CLOSED", "closed_port")

        self.end_time_of_scan = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.scan_completed = True

        # Clear live progress lines before showing final results
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)

        self.render_final_results(scanned_count, open_ports, closed_ports)

        self.update_scan_progress(100, f"Scan complete: {scanned_count} ports scanned")
        self.enable_scan_button()
    
        if hasattr(self, "parent_gui"):
            self.parent_gui.status_label.config(
                text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Port scan complete"
            )

        # Update parent GUI with latest scan summary for dashboard display
        if hasattr(self, "parent_gui"):
            summary_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.parent_gui.latest_port_scanner_summary = (
                f"Time: {summary_time}\n"
                f"Scanned: {scanned_count} ports\n"
                f"Open: {len(open_ports)}\n"
                f"Closed: {len(closed_ports)}"
            )
            self.parent_gui.update_security_dashboard()

    def render_final_results(self, scanned_count, open_ports, closed_ports):
        """Render final scan results based on the selected filter."""
        filter_type = self.filter_var.get()

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)

        # Summary at the top
        self.output_text.insert(tk.END, f"Scan complete. [{self.end_time_of_scan}]\n", "header")
        self.output_text.insert(tk.END, f"Total ports scanned: {scanned_count}\n", "info")

        if filter_type == "all":
            self.output_text.insert(tk.END, f"Open ports: {len(open_ports)}\n", "open_port")
            self.output_text.insert(tk.END, f"Closed ports: {len(closed_ports)}\n", "closed_port")
            self.output_text.insert(tk.END, "-" * 140 + "\n", "info")
            self.render_all_results_two_columns(open_ports, closed_ports)

        elif filter_type == "open":
            self.output_text.insert(tk.END, f"Open ports: {len(open_ports)}\n", "open_port")
            self.output_text.insert(tk.END, "-" * 80 + "\n", "info")
            self.render_filtered_results(open_ports, "open")

        elif filter_type == "closed":
            self.output_text.insert(tk.END, f"Closed ports: {len(closed_ports)}\n", "closed_port")
            self.output_text.insert(tk.END, "-" * 80 + "\n", "info")
            self.render_filtered_results(closed_ports, "closed")

        self.output_text.config(state=tk.DISABLED)

    def render_all_results_two_columns(self, open_ports, closed_ports):
        """Render open and closed ports side by side in one display box."""
        left_width = 88
        divider_width = 140

        # Headers
        self.output_text.insert(tk.END, "OPEN PORTS".ljust(left_width), "header")
        self.output_text.insert(tk.END, "CLOSED PORTS\n", "header")
        self.output_text.insert(tk.END, "-" * divider_width + "\n", "info")

        max_len = max(len(open_ports), len(closed_ports))

        for i in range(max_len):
            open_result = open_ports[i] if i < len(open_ports) else None
            closed_result = closed_ports[i] if i < len(closed_ports) else None

            # Main line for open side
            if open_result:
                open_line = f"{i+1}. [{open_result['timestamp']}] Port {open_result['port']}: OPEN"
                self.output_text.insert(tk.END, open_line, "open_port")
            else:
                open_line = ""

            # Padding to move to the closed column
            padding = max(1, left_width - len(open_line))
            self.output_text.insert(tk.END, " " * padding)

            # Main line for closed side
            if closed_result:
                closed_line = f"{i+1}. [{closed_result['timestamp']}] Port {closed_result['port']}: CLOSED"
                self.output_text.insert(tk.END, closed_line, "closed_port")

            self.output_text.insert(tk.END, "\n")

            # Open-port service line
            if open_result and open_result["service"] != "N/A":
                self.output_text.insert(
                    tk.END,
                    f"      └─ Service: {open_result['service']}\n",
                    "service"
                )

            # Open-port warning line
            if open_result and open_result["security_note"] != "N/A":
                self.output_text.insert(
                    tk.END,
                    f"      └─ {open_result['security_note']}\n",
                    "warning"
                )

            # Blank line between entries
            self.output_text.insert(tk.END, "\n")

    def render_filtered_results(self, filtered_results, mode):
        """Render filtered results in the original single-list style."""
        for index, result in enumerate(filtered_results, start=1):
            line = f"{index}. [{result['timestamp']}] Port {result['port']}: {result['status']}\n"

            if mode == "open":
                self.output_text.insert(tk.END, line, "open_port")
            else:
                self.output_text.insert(tk.END, line, "closed_port")

            if result["service"] != "N/A":
                self.output_text.insert(tk.END, f"   └─ Service: {result['service']}\n", "service")

            if result["security_note"] != "N/A":
                self.output_text.insert(tk.END, f"   └─ {result['security_note']}\n", "warning")

            self.output_text.insert(tk.END, "\n")

    def start_scan(self):
        """
        Start a new port scan in a background thread.

        Validates user input, clears old results, and prepares the UI.
        """
        # Prevent multiple simultaneous scans
        if self.scanning:
            return
        
        if hasattr(self, "parent_gui"):
            self.parent_gui.status_label.config(
                text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Scanning ports"
            )

        # Read user input
        host = self.ip_entry.get().strip()
        port_input = self.port_entry.get().strip()
        
        # Validate input
        valid, error_msg, port_list = self.validate_inputs(host, port_input)

        if not valid:
           # Show validation error
            self.display_output(error_msg)
            messagebox.showerror("Input Error", error_msg)
            return
        
        # Reset previous scan data
        self.clear_results()
        
        # Mark scan as active
        self.scanning = True
        self.scan_completed = False  # Reset scan completed flag for new scan

        self.scan_button.config(state=tk.DISABLED, text="Scanning...")
        
       # Run scan in background so the GUI stays responsive
        scan_thread = threading.Thread(
            target=self.perform_scan,           # Function to run in thread
            args=(host, port_list),             # Arguments to pass
            daemon=True                         # Auto-terminate with main program
        )
        scan_thread.start()
        
        # Update button states
        self.scan_button.config(state=tk.DISABLED, text="Scanning...")  # Disable start
        self.stop_scan_button.config(state=tk.NORMAL)                    # Enable stop
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.scanning = False
            self.display_output("\nScan cancelled by user.", "warning")

        if hasattr(self, "parent_gui"):
            self.parent_gui.status_label.config(
                text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Scan cancelled"
            )
    
    def enable_scan_button(self):
        """Safely re-enable the scan button after scanning completes."""
        self.parent_frame.after(0, self._enable_scan_button_gui)

    def _enable_scan_button_gui(self):
        """Actual GUI update for scan button state."""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL, text="Start Scan")
        self.stop_scan_button.config(state=tk.DISABLED)
# ==================== NETWORK ANALYZER CLASS ====================
class NetworkAnalyzer:
    """
    Network Traffic Analyzer module.

    Purpose:
        Captures and analyzes live network traffic for monitoring and basic reconnaissance.

    Main responsibilities:
        - Capture packets using protocol and port filters
        - Display packet information in real time
        - Summarize top destination ports and IP addresses
        - Export packet data and traffic summaries
        - Support integration with the Port Scanner through clickable IPs
    """
    
    def __init__(self, parent_frame):
        """Initialize the Network Analyzer GUI and variables"""
        self.parent_frame = parent_frame
        self.capturing = False  # Flag to track if capture is in progress
        self.packet_count = 0
        self.capture_thread = None
        self.start_time = None  # Track capture start time
        self.end_time = None  # Track capture end time
        self.all_packets = []  # Store all captured packets for filtering
        self.capture_data = []  # Store packet data for export (timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info)
        self.capture_session_header = ""
        self.capture_completion_summary = ""

        # Data structures for reconnaissance and information gathering
        self.destination_ports = {}  # Dictionary to count destination ports
        self.destination_ips = {}    # Dictionary to count destination IPs
        self.ip_to_domain = {}       # Cache for reverse DNS lookups
        self.ip_to_domain_from_traffic = {}  # Domain names extracted from packet payloads (SNI, HTTP Host)
        self.known_ports = {}       # Ports 0-1023
        self.ephemeral_ports = {}   # Ports 49152-65535

        # Capture filter tracking
        self.captured_protocol = None  # Store the protocol filter used during capture ('all', 'tcp', 'udp', 'icmp')
        self.selected_capture_mode = "Max Packets"  # Default capture mode (can be "Max Packets" or "Timeout")

        self.detected_ports_set = set() # Store unique dected ports for dropdown menu
        
        # Create GUI elements
        self.create_widgets()

    def on_mode_change(self, event=None):
        """Handle changes in capture mode (Max Packets vs Timeout)"""
        mode = self.capture_mode.get()
        self.selected_capture_mode = mode

        self.capture_mode_value_entry.delete(0, tk.END)

        if mode == "Max Packets":
            self.capture_mode_value_entry.insert(0, "100")
        else:  # Timeout (second/s)
            self.capture_mode_value_entry.insert(0, "10")
    
    def update_detected_port_dropdown(self):
        """Update detected port dropdown with ports found in captured traffic."""

        # for p in sorted(self.detected_ports_set):
        #    print(f"Detected port: {p}")  # Debug print to verify detected ports are being tracked
        
        
        # Create a sorted list of unique detected ports, prefixed with "All" for no filter
        port_values = ["All"] + [str(p) for p in sorted(self.detected_ports_set)] 
        self.detected_port_dropdown["values"] = port_values # Update dropdown options with new port list

        # If current selected value is no longer valid, reset to All
        if self.detected_port_var.get() not in port_values:
            self.detected_port_var.set("All")

    def create_widgets(self):
        """Create and arrange all GUI elements for traffic analyzer"""        
        
        # Check if Scapy is available
        if not SCAPY_AVAILABLE:
            warning_frame = tk.Frame(self.parent_frame, bg="#e74c3c", padx=10, pady=10)
            warning_frame.pack(pady=10, padx=20, fill=tk.X)
            
            warning_label = tk.Label(
                warning_frame,
                text="⚠ Scapy is not installed. Please install it using: pip install scapy",
                font=("Arial", 10, "bold"),
                fg="white",
                bg="#e74c3c",
                wraplength=500
            )
            warning_label.pack()
            
            info_label = tk.Label(
                self.parent_frame,
                text="Note: This module requires administrator/root privileges to capture network traffic.",
                font=("Arial", 10, "italic"),
                fg="#7f8c8d"
            )
            info_label.pack(pady=5)
            return
        
        # Filter Frame
        filter_frame = tk.LabelFrame(self.parent_frame, text="Capture Filters", font=("Arial", 10, "bold"))
        filter_frame.configure(bg="#ffffff")
        filter_frame.pack(pady=10, padx=20, fill=tk.X)
        
        # Protocol Filter
        tk.Label(filter_frame, text="Protocol:", bg="#ffffff", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, padx=10, pady=5)
        protocol_frame = tk.Frame(filter_frame)
        protocol_frame.grid(row=0, column=1, sticky=tk.W, padx=10, pady=5)
        
        self.protocol_var = tk.StringVar(value="all")  # Default to all protocols
        tk.Radiobutton(protocol_frame, text="All", variable=self.protocol_var, value="all").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(protocol_frame, text="TCP", variable=self.protocol_var, value="tcp").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(protocol_frame, text="UDP", variable=self.protocol_var, value="udp").pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(protocol_frame, text="ICMP", variable=self.protocol_var, value="icmp").pack(side=tk.LEFT, padx=5)
        
        # Port Filter
        tk.Label(filter_frame, text="Port (optional):", bg="#ffffff", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, padx=10, pady=5)
        self.port_entry = tk.Entry(filter_frame, width=15, font=("Arial", 10))
        self.port_entry.grid(row=1, column=1, sticky=tk.W, padx=10, pady=5)        

        tk.Label(filter_frame, text="Format examples: 80 (HTTP), 443 (HTTPS), 53 (DNS), 22 (SSH)", 
                bg="#ffffff", font=("Arial", 8, "italic"), fg="#7f8c8d").grid(row=2, column=0, columnspan=2, sticky=tk.W, padx=10, pady=2)
        
        self.capture_mode = tk.StringVar(value="Max Packets")        

        self.mode_dropdown = ttk.Combobox(
            filter_frame,
            textvariable=self.capture_mode,
            values=["Max Packets", "Timeout (second/s)"],
            state="readonly",
            width=18
        )
        
        self.mode_dropdown.grid(row=3, column=0, sticky=tk.W, padx=10, pady=5)        
        self.mode_dropdown.bind("<<ComboboxSelected>>", self.on_mode_change)

        self.capture_mode_value_entry = tk.Entry(filter_frame, width=15, font=("Arial", 10))
        self.capture_mode_value_entry.grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)
        self.capture_mode_value_entry.insert(0, "100")  # Default to 100 packets for analysis 

        tk.Label(
            filter_frame,
            text="Packet limit: minimum 1, maximum 10000",
            bg="#ffffff",
            font=("Arial", 8, "italic"),
            fg="#7f8c8d"
        ).grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 2))

        tk.Label(
            filter_frame,
            text="Timeout range: minimum 1 second, maximum 3600 seconds",
            bg="#ffffff",
            font=("Arial", 8, "italic"),
            fg="#7f8c8d"
        ).grid(row=5, column=0, columnspan=2, sticky=tk.W, padx=10, pady=(0, 5))     
        
        # Info Label
        info_label = tk.Label(
            self.parent_frame,
            text="⚠ Requires administrator/root privileges. Captures TCP traffic for reconnaissance & provides Top 5 summaries.",
            font=("Arial", 10, "italic"),
            fg="#e67e22"
        )
        info_label.pack(pady=5)
        
        # Button Frame
        button_frame = tk.Frame(self.parent_frame)
        button_frame.pack(pady=10)
        
        # Start Capture Button
        self.start_button = tk.Button(
            button_frame, 
            text="Start Capture", 
            command=self.start_capture,
            bg="#27ae60",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2"
        )
        self.start_button.grid(row=0, column=0, padx=5)
        
        # Stop Capture Button
        self.stop_button = tk.Button(
            button_frame, 
            text="Stop Capture", 
            command=self.stop_capture,
            bg="#e74c3c",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.stop_button.grid(row=0, column=1, padx=5)
        
        # Clear Button
        self.clear_button = tk.Button(
            button_frame, 
            text="Clear Results", 
            command=self.clear_results,
            bg="#3498db",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2"
        )
        self.clear_button.grid(row=0, column=2, padx=5)
        
        # Export Button
        self.export_button = tk.Button(
            button_frame, 
            text="Export Results", 
            command=self.export_results,
            bg="#9b59b6",
            fg="white",
            font=("Arial", 10, "bold"),
            width=15,
            cursor="hand2"
        )
        self.export_button.grid(row=0, column=3, padx=5)
        
        # Filter Frame for Results
        filter_result_frame = tk.Frame(self.parent_frame)
        filter_result_frame.pack(pady=5, padx=20, fill=tk.X)
        
        tk.Label(filter_result_frame, text="Filter Results:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar(value="all")        
        self.filter_var.set("all")  # Default to showing all results
        tk.Radiobutton(filter_result_frame, text="All"          , variable=self.filter_var, value="all"     , command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_result_frame, text="TCP Only"     , variable=self.filter_var, value="tcp"     , command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_result_frame, text="UDP Only"     , variable=self.filter_var, value="udp"     , command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_result_frame, text="ICMP Only"    , variable=self.filter_var, value="icmp"    , command=self.apply_filter).pack(side=tk.LEFT, padx=5)
        tk.Radiobutton(filter_result_frame, text="Summary Only" , variable=self.filter_var, value="summary" , command=self.apply_filter).pack(side=tk.LEFT, padx=5)        

        # Advanced Filter Inputs
        advanced_filter_frame = tk.Frame(self.parent_frame)
        advanced_filter_frame.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(advanced_filter_frame, text="IP Filter:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.ip_filter_entry = tk.Entry(advanced_filter_frame, width=18, font=("Arial", 10))
        self.ip_filter_entry.pack(side=tk.LEFT, padx=5)

        tk.Label(advanced_filter_frame, text="Port Filter:", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.port_filter_entry = tk.Entry(advanced_filter_frame, width=10, font=("Arial", 10))
        self.port_filter_entry.pack(side=tk.LEFT, padx=5)

        tk.Button(
            advanced_filter_frame,
            text="Apply Advanced Filter",
            command=self.apply_filter,
            bg="#95a5a6",
            fg="white",
            font=("Arial", 10, "bold"),
            cursor="hand2"
        ).pack(side=tk.LEFT, padx=8)
        

        # Detected Port Dropdown Filter
        port_dropdown_frame = tk.Frame(self.parent_frame)
        port_dropdown_frame.pack(pady=5, padx=20, fill=tk.X)

        tk.Label(port_dropdown_frame, text="Detected Port Filter:", 
                 font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)

        self.detected_port_var = tk.StringVar(value="All")
        self.detected_port_dropdown = ttk.Combobox(
            port_dropdown_frame,
            textvariable=self.detected_port_var,
            values=["All"],
            state="readonly",
            width=15
        )
        self.detected_port_dropdown.pack(side=tk.LEFT, padx=5)
        self.detected_port_dropdown.bind("<<ComboboxSelected>>", self.apply_filter)


        # Output Frame
        output_frame = tk.Frame(self.parent_frame)
        output_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)
        
        tk.Label(output_frame, text="Capture Results:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        
        # Scrolled Text Widget for Output
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            width=80,
            height=12,
            font=("Consolas", 9),
            bg="#ecf0f1",
            fg="#2c3e50",
            wrap=tk.WORD
        )
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # Configure text tags for color-coding
        self.output_text.tag_config("tcp", foreground="#3498db", font=("Consolas", 9))
        self.output_text.tag_config("udp", foreground="#9b59b6", font=("Consolas", 9))
        self.output_text.tag_config("icmp", foreground="#e67e22", font=("Consolas", 9))
        self.output_text.tag_config("summary", foreground="#2c3e50", font=("Consolas", 9, "bold"))
        self.output_text.tag_config("header", foreground="#27ae60", font=("Consolas", 10, "bold"))
        self.output_text.tag_config("info", foreground="#34495e", font=("Consolas", 9))
    
    def render_capture_completion_summary(self):
        """Render the saved completion summary with consistent colors."""
        if not self.capture_completion_summary:
            return

        lines = self.capture_completion_summary.split("\n")

        for line in lines:
            if line.startswith("="):
                self.output_text.insert(tk.END, line + "\n", "header")
            elif line.startswith("Capture completed at:") or line.startswith("Capture stopped by user at:"):
                self.output_text.insert(tk.END, line + "\n", "header")
            else:
                self.output_text.insert(tk.END, line + "\n", "summary")

        self.output_text.insert(tk.END, "\n")

    def display_output(self, message, tag=None):
        """Safely display a message in the output text widget."""
        self.all_packets.append((message, tag))
        self.parent_frame.after(0, lambda: self._display_output_gui(message, tag))


    def _display_output_gui(self, message, tag=None):
        """Actual GUI update for capture output."""
        self.output_text.config(state=tk.NORMAL)
        if tag:
            self.output_text.insert(tk.END, message + "\n", tag)
        else:
            self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def insert_clickable_ip_line(self, rank, ip, domain, count, percentage):
        """Insert a summary line where the IP is clickable inside output_text."""
        tag = f"ip_link_{rank}_{ip.replace('.', '_')}"

        self.output_text.config(state=tk.NORMAL)

        self.output_text.insert(tk.END, f"  #{rank}  ", "summary")
        self.output_text.insert(tk.END, f"{ip}", (tag, "summary"))

        if domain and domain != ip:
            self.output_text.insert(tk.END, f" → {domain} - {count} packets ({percentage:.1f}%)\n", "summary")
        else:
            self.output_text.insert(tk.END, f" → No domain found - {count} packets ({percentage:.1f}%)\n", "summary")

        self.output_text.tag_config(tag, underline=True, foreground="#00E5FF")
        self.output_text.tag_bind(tag, "<Button-1>", lambda e, ip=ip: self.handle_ip_click(ip))
        self.output_text.tag_bind(tag, "<Enter>", lambda e: self.output_text.config(cursor="hand2"))
        self.output_text.tag_bind(tag, "<Leave>", lambda e: self.output_text.config(cursor=""))

        self.output_text.see(tk.END)

    def _insert_clickable_ip_line_gui(self, rank, ip, domain, count, percentage):
        """Insert one clickable IP summary line into the output."""
        tag = f"ip_link_{rank}_{ip.replace('.', '_')}"

        self.output_text.config(state=tk.NORMAL)

        self.output_text.insert(tk.END, f"  #{rank}  ", "summary")
        self.output_text.insert(tk.END, f"{ip}", (tag, "summary"))

        if domain and domain != ip:
            self.output_text.insert(
                tk.END,
                f" → {domain} - {count} packets ({percentage:.1f}%)\n",
                "summary"
            )
        else:
            self.output_text.insert(
                tk.END,
                f" → No domain found - {count} packets ({percentage:.1f}%)\n",
                "summary"
            )

        self.output_text.tag_config(tag, underline=True, foreground="#00E5FF")
        self.output_text.tag_bind(tag, "<Button-1>", lambda e, ip=ip: self.handle_ip_click(ip))
        self.output_text.tag_bind(tag, "<Enter>", lambda e: self.output_text.config(cursor="hand2"))
        self.output_text.tag_bind(tag, "<Leave>", lambda e: self.output_text.config(cursor=""))

        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def handle_ip_click(self, ip):
        """If GUI provided a callback, call it when an IP is clicked."""
        if hasattr(self, "on_ip_click") and callable(self.on_ip_click):
            self.on_ip_click(ip)
        
    def apply_filter(self, event=None):
        """Apply protocol, IP, and port filters to traffic capture results display."""
        filter_type = self.filter_var.get()
        ip_filter = self.ip_filter_entry.get().strip()
        port_filter = self.port_filter_entry.get().strip()

        # Warn if protocol filter doesn't match captured protocol
        if self.captured_protocol and filter_type not in ["all", "summary"]:
            if self.captured_protocol != "all" and filter_type != self.captured_protocol:
                messagebox.showwarning(
                    "Filter Mismatch",
                    f"You captured only {self.captured_protocol.upper()} traffic.\n"
                    f"Filtering by {filter_type.upper()} may show no packet data."
                )

        # Summary Only -> redraw summary screen only
        if filter_type == "summary":
            self.display_traffic_summary(summary_only=True)
            return

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)

        # Rebuild the short top capture summary with proper colors
        self.render_capture_session_header()

        filtered_data = self.get_filtered_data()

        # Show visible filter summary
        filter_parts = []

        if filter_type not in ["all", "summary"]:
            filter_parts.append(f"Protocol = {filter_type.upper()}")

        if ip_filter:
            filter_parts.append(f"IP = {ip_filter}")

        if port_filter:
            filter_parts.append(f"Port = {port_filter}")

        selected_port = self.detected_port_var.get()
        if selected_port != "All":
            filter_parts.append(f"Detected Port = {selected_port}")

        if filter_parts:
            self.output_text.insert(
                tk.END,
                "Advanced filter applied: " + ", ".join(filter_parts) + "\n\n",
                "summary"
            )

        if port_filter:
            try:
                int(port_filter)
            except ValueError:
                self.output_text.insert(tk.END, "Invalid Port Filter. Enter a valid integer.\n", "info")
                self.output_text.config(state=tk.DISABLED)
                return

        # Render packet list
        for data in filtered_data:
            timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info = data
            output_line = f"[{timestamp}] {protocol:6} | SRC: {src_ip:15}:{str(src_port):5} | DST: {dst_ip:15}:{str(dst_port):5}"
            if info:
                output_line += f" | {info}"

            tag = None
            if protocol == "TCP":
                tag = "tcp"
            elif protocol == "UDP":
                tag = "udp"
            elif protocol == "ICMP":
                tag = "icmp"

            if tag:
                self.output_text.insert(tk.END, output_line + "\n", tag)
            else:
                self.output_text.insert(tk.END, output_line + "\n")

        # In ALL view, append the reconnaissance summary under the packet list
        if filter_type == "all" and self.packet_count > 0:
            self.output_text.insert(tk.END, "\n")
            self.render_capture_completion_summary()
            self.display_traffic_summary(summary_only=False)
        
    def clear_results(self):
        """Clear the output text widget and reset analysis data"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.packet_count = 0
        self.all_packets = []  # Clear stored packets
        self.capture_data = []  # Clear export data
        
        # Reset reconnaissance data structures
        self.destination_ports.clear()
        self.destination_ips.clear()
        self.ip_to_domain.clear()
        self.ip_to_domain_from_traffic.clear()
        self.known_ports.clear()
        self.ephemeral_ports.clear()
        
        # Reset captured protocol filter
        self.captured_protocol = None

        # Clear advanced filter inputs
        self.ip_filter_entry.delete(0, tk.END)
        self.port_filter_entry.delete(0, tk.END)

        # Clear detected ports dropdown
        self.detected_ports_set.clear()
        self.detected_port_var.set("All")
        self.detected_port_dropdown["values"] = ["All"]
        
    def get_filtered_data(self):
        """Get capture data filtered by protocol, IP address, and port."""
        protocol_filter = self.filter_var.get()
        ip_filter = self.ip_filter_entry.get().strip()
        port_filter = self.port_filter_entry.get().strip()
        selected_port = self.detected_port_var.get()

        filtered_data = []

        for data in self.capture_data:
            # returned data [timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info]
            timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info = data

            # 1. Filter by protocol
            if protocol_filter != "all" and protocol_filter != "summary":
                if protocol.upper() != protocol_filter.upper():
                    continue                

            # 2. Filter by IP
            if ip_filter:
                if ip_filter != src_ip and ip_filter != dst_ip:
                    continue

            # 3. Filter by Port
            if port_filter:
                try:
                    port_num = int(port_filter)
                    if src_port != port_num and dst_port != port_num:
                        continue
                except ValueError:
                    # Invalid port filter - skip all results
                    return []
                
            # 4. Filter by Detected Port Dropdown
            if selected_port != "All":
                try:
                    port_num = int(selected_port)
                    if src_port != port_num and dst_port != port_num:
                        continue
                except ValueError:
                    continue

            # If it passes all filters, include in results
            filtered_data.append(data)
        
        return filtered_data

    def export_results(self):
        """Export capture results to file (respects current filter setting)"""
        if not self.capture_data:
            messagebox.showwarning("No Data", "No capture data to export. Please run a capture first.")
            return
        
        # Get filtered data based on current filter
        filter_type = self.filter_var.get()
        
        # For summary export, we'll export analytical data instead of packet data
        if filter_type == "summary":
            self.export_summary()
            return
        
        filtered_data = self.get_filtered_data()
        
        # Check if there's any data to export after filtering
        if not filtered_data:
            messagebox.showwarning("No Data", f"No {filter_type.upper()} packets to export with current filter setting.")
            return
        
        # Create dialog to choose file format
        format_dialog = tk.Toplevel(self.parent_frame)
        format_dialog.title("Select Export Format")
        format_dialog.geometry("400x280")
        format_dialog.resizable(True, True)
        format_dialog.grab_set()  # Make it modal
        format_dialog.transient(self.parent_frame)
        
        # Center the dialog on screen
        format_dialog.update_idletasks()
        dialog_width = format_dialog.winfo_width()
        dialog_height = format_dialog.winfo_height()
        screen_width = format_dialog.winfo_screenwidth()
        screen_height = format_dialog.winfo_screenheight()
        x_position = (screen_width - dialog_width) // 2
        y_position = (screen_height - dialog_height) // 2
        format_dialog.geometry(f"{dialog_width}x{dialog_height}+{x_position}+{y_position}")
        
        selected_format = tk.StringVar(value="txt")
        
        tk.Label(format_dialog, text="Choose Export Format:", font=("Arial", 12, "bold")).pack(pady=15)
        
        format_frame = tk.Frame(format_dialog)
        format_frame.pack(pady=10)
        
        tk.Radiobutton(format_frame, text="Text File (.txt) - Human readable format", 
                      variable=selected_format, value="txt", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(format_frame, text="CSV File (.csv) - Spreadsheet compatible", 
                      variable=selected_format, value="csv", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(format_frame, text="JSON File (.json) - Structured data format", 
                      variable=selected_format, value="json", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        
        result_container = {'format': None}
        
        def on_proceed():
            result_container['format'] = selected_format.get()
            format_dialog.destroy()
        
        def on_cancel():
            format_dialog.destroy()
        
        button_frame = tk.Frame(format_dialog)
        button_frame.pack(pady=15)
        
        tk.Button(button_frame, text="Proceed", command=on_proceed, bg="#27ae60", fg="white", 
                 font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=on_cancel, bg="#e74c3c", fg="white", 
                 font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        # Wait for the dialog to close
        format_dialog.wait_window()
        
        if not result_container['format']:
            return
        
        # Generate auto filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_format = result_container['format']
        default_filename = f"traffic_capture_{timestamp}.{file_format}"
        
        # Determine file types based on selection
        if file_format == 'txt':
            file_types = [("Text File", "*.txt")]
            default_ext = ".txt"
        elif file_format == 'csv':
            file_types = [("CSV File", "*.csv")]
            default_ext = ".csv"
        else:  # json
            file_types = [("JSON File", "*.json")]
            default_ext = ".json"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=file_types,
            initialfile=default_filename,
            title="Save Traffic Capture Results"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)

                    writer.writerow(["NETWORK TRAFFIC CAPTURE RESULTS"])
                    writer.writerow(["=" * 100])

                    if self.start_time:
                        writer.writerow([f"Capture Started:   {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}"])
                    if self.end_time:
                        writer.writerow([f"Capture Ended:     {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}"])
                        if self.start_time:
                            duration = (self.end_time - self.start_time).total_seconds()
                            writer.writerow([f"Duration:          {duration:.2f} seconds"])

                    writer.writerow([f"Filter Applied:    {filter_type.upper()}"])
                    writer.writerow([f"Total Packets:     {self.packet_count}"])
                    writer.writerow([f"Exported Packets:  {len(filtered_data)}"])
                    writer.writerow([f"Unique Dest IPs:   {len(self.destination_ips)}"])
                    writer.writerow([f"Unique Dest Ports: {len(self.destination_ports)}"])

                    writer.writerow(["=" * 100])

                    writer.writerow(['Timestamp', 'Protocol', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Info'])
                    for data in filtered_data:
                        writer.writerow(data)
                        
            elif file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json_data = [
                        {
                            'timestamp': data[0],
                            'protocol': data[1],
                            'source_ip': data[2],
                            'source_port': data[3],
                            'destination_ip': data[4],
                            'destination_port': data[5],
                            'info': data[6]
                        } for data in filtered_data
                    ]
                    
                    # Add capture session metadata
                    export_data = {
                        'capture_session': {
                            'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A',
                            'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A',
                            'filter_applied': filter_type.upper(),
                            'total_packets_captured': self.packet_count,
                            'exported_packets': len(filtered_data),
                            'unique_destination_ips': len(self.destination_ips),
                            'unique_destination_ports': len(self.destination_ports)
                        },
                        'packets': json_data
                    }
                    json.dump(export_data, f, indent=2)
            else:  # TXT
                with open(file_path, 'w', encoding='utf-8') as f:
                    # ============================================================
                    # SECTION 1: CAPTURE SESSION INFO
                    # ============================================================
                    f.write("NETWORK TRAFFIC CAPTURE RESULTS\n")
                    f.write("=" * 100 + "\n\n")

                    if self.start_time:
                        f.write(f"Capture Started:   {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    if self.end_time:
                        f.write(f"Capture Ended:     {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        if self.start_time:
                            duration = (self.end_time - self.start_time).total_seconds()
                            f.write(f"Duration:          {duration:.2f} seconds\n")

                    f.write(f"Filter Applied:    {filter_type.upper()}\n")
                    f.write(f"Total Packets:     {self.packet_count}\n")
                    f.write(f"Exported Packets:  {len(filtered_data)}\n")
                    f.write(f"Unique Dest IPs:   {len(self.destination_ips)}\n")
                    f.write(f"Unique Dest Ports: {len(self.destination_ports)}\n")
                    f.write("\n" + "=" * 100 + "\n\n")

                    # ============================================================
                    # SECTION 2: CAPTURED PACKETS
                    # ============================================================
                    f.write("CAPTURED PACKETS:\n")
                    f.write("-" * 100 + "\n")
                    for data in filtered_data:
                        timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info = data
                        f.write(f"[{timestamp}] {protocol:6} | SRC: {src_ip:15}:{str(src_port):5} | DST: {dst_ip:15}:{str(dst_port):5}")
                        if info:
                            f.write(f" | {info}")
                        f.write("\n")

                    f.write("\n" + "=" * 100 + "\n")
                    f.write("TRAFFIC ANALYSIS & INFORMATION GATHERING\n")
                    f.write("=" * 100 + "\n\n")

                    # ============================================================
                    # SECTION 3: TOP 5 DESTINATION PORTS
                    # ============================================================
                    common_services = {
                        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
                        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
                        143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
                        3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
                    }

                    top_ports = sorted(self.destination_ports.items(), key=lambda x: x[1], reverse=True)[:5]
                    top_ips = sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:5]

                    f.write("TOP 5 DESTINATION PORTS (Most Accessed Services):\n")
                    f.write("-" * 100 + "\n")
                    if top_ports:
                        for rank, (port, count) in enumerate(top_ports, 1):
                            service_name = common_services.get(port, "Unknown/Ephemeral")
                            percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
                            f.write(f"  #{rank}  Port {port:5} ({service_name:15}) - {count:4} packets ({percentage:5.1f}%)\n")
                    else:
                        f.write("  No destination port data collected.\n")

                    f.write("\n")

                    # ============================================================
                    # SECTION 4: TOP 5 DESTINATION IPS
                    # ============================================================
                    f.write("TOP 5 DESTINATION IP ADDRESSES (Most Contacted Servers/Websites):\n")
                    f.write("-" * 100 + "\n")
                    if top_ips:
                        for rank, (ip, count) in enumerate(top_ips, 1):
                            domain = self.resolve_ip_to_domain(ip)
                            percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
                            if domain != ip:
                                f.write(f"  #{rank}  {ip:15} → {domain:40} - {count:4} packets ({percentage:5.1f}%)\n")
                            else:
                                f.write(f"  #{rank}  {ip:15} → No domain found via reverse DNS - {count:4} packets ({percentage:5.1f}%)\n")
                    else:
                        f.write("  No destination IP data collected.\n")

                    f.write("\n")

                    # ============================================================
                    # SECTION 5: KEY INSIGHTS
                    # ============================================================
                    f.write("KEY INSIGHTS:\n")
                    f.write("-" * 100 + "\n")

                    if 443 in self.destination_ports:
                        https_count = self.destination_ports[443]
                        https_percent = (https_count / self.packet_count) * 100 if self.packet_count > 0 else 0
                        f.write(f"  ✓ {https_percent:.1f}% of traffic uses HTTPS (Port 443) - Good security practice!\n")

                    if 80 in self.destination_ports:
                        http_count = self.destination_ports[80]
                        http_percent = (http_count / self.packet_count) * 100 if self.packet_count > 0 else 0
                        f.write(f"  ⚠ {http_percent:.1f}% of traffic uses unencrypted HTTP (Port 80) - Consider using HTTPS\n")

                    ephemeral_count = sum(count for port, count in self.destination_ports.items() if port >= 49152)
                    if ephemeral_count > 0:
                        ephemeral_percent = (ephemeral_count / self.packet_count) * 100 if self.packet_count > 0 else 0
                        f.write(f"  ℹ {ephemeral_percent:.1f}% uses ephemeral ports (49152-65535) - Normal for client connections\n")

                    if len(self.destination_ips) > 20:
                        f.write(f"  ℹ High connection diversity ({len(self.destination_ips)} unique IPs) - Active web browsing/multi-service usage\n")
                    elif len(self.destination_ips) < 5:
                        f.write(f"  ℹ Low connection diversity ({len(self.destination_ips)} unique IPs) - Focused activity on few services\n")

                    f.write("\n" + "=" * 100 + "\n")
            
            messagebox.showinfo("Success", f"Capture results exported to:\n{file_path}\n\nFilter: {filter_type.upper()}\nExported: {len(filtered_data)} of {self.packet_count} packets")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")
    
    def export_summary(self):
        """Export traffic analysis summary to file"""
        # Create dialog to choose file format
        format_dialog = tk.Toplevel(self.parent_frame)
        format_dialog.title("Select Export Format")
        format_dialog.geometry("400x280")
        format_dialog.resizable(True, True)
        format_dialog.grab_set()  # Make it modal
        format_dialog.transient(self.parent_frame)
        
        # Center the dialog on screen
        format_dialog.update_idletasks()
        dialog_width = format_dialog.winfo_width()
        dialog_height = format_dialog.winfo_height()
        screen_width = format_dialog.winfo_screenwidth()
        screen_height = format_dialog.winfo_screenheight()
        x_position = (screen_width - dialog_width) // 2
        y_position = (screen_height - dialog_height) // 2
        format_dialog.geometry(f"{dialog_width}x{dialog_height}+{x_position}+{y_position}")
        
        selected_format = tk.StringVar(value="txt")
        
        tk.Label(format_dialog, text="Choose Export Format:", font=("Arial", 12, "bold")).pack(pady=15)
        
        format_frame = tk.Frame(format_dialog)
        format_frame.pack(pady=10)
        
        tk.Radiobutton(format_frame, text="Text File (.txt) - Human readable format", 
                      variable=selected_format, value="txt", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(format_frame, text="CSV File (.csv) - Spreadsheet compatible", 
                      variable=selected_format, value="csv", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        tk.Radiobutton(format_frame, text="JSON File (.json) - Structured data format", 
                      variable=selected_format, value="json", font=("Arial", 10)).pack(anchor=tk.W, padx=20, pady=5)
        
        result_container = {'format': None}
        
        def on_proceed():
            result_container['format'] = selected_format.get()
            format_dialog.destroy()
        
        def on_cancel():
            format_dialog.destroy()
        
        button_frame = tk.Frame(format_dialog)
        button_frame.pack(pady=15)
        
        tk.Button(button_frame, text="Proceed", command=on_proceed, bg="#27ae60", fg="white", 
                 font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=on_cancel, bg="#e74c3c", fg="white", 
                 font=("Arial", 10, "bold"), width=12, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        # Wait for the dialog to close
        format_dialog.wait_window()
        
        if not result_container['format']:
            return
        
        # Generate auto filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        file_format = result_container['format']
        default_filename = f"traffic_summary_{timestamp}.{file_format}"
        
        # Determine file types based on selection
        if file_format == 'txt':
            file_types = [("Text File", "*.txt")]
            default_ext = ".txt"
        elif file_format == 'csv':
            file_types = [("CSV File", "*.csv")]
            default_ext = ".csv"
        else:  # json
            file_types = [("JSON File", "*.json")]
            default_ext = ".json"
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=file_types,
            initialfile=default_filename,
            title="Save Traffic Analysis Summary"
        )
        
        if not file_path:
            return
        
        try:
            # Prepare summary data
            common_services = {
                20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
                25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
                143: "IMAP", 443: "HTTPS", 445: "SMB", 3306: "MySQL",
                3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-ALT", 8443: "HTTPS-ALT"
            }
            
            top_ports = sorted(self.destination_ports.items(), key=lambda x: x[1], reverse=True)[:5]
            top_ips = sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:5]
            
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    
                    # Session info
                    writer.writerow(['TRAFFIC ANALYSIS SUMMARY'])
                    writer.writerow(['Capture Start', self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'])
                    writer.writerow(['Capture End', self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else 'N/A'])
                    if self.start_time and self.end_time:
                        duration = (self.end_time - self.start_time).total_seconds()
                        writer.writerow(['Duration (seconds)', f'{duration:.2f}'])
                    writer.writerow(['Total Packets', self.packet_count])
                    writer.writerow(['Unique Destination IPs', len(self.destination_ips)])
                    writer.writerow(['Unique Destination Ports', len(self.destination_ports)])
                    writer.writerow([])
                    
                    # Top 5 ports
                    writer.writerow(['TOP 5 DESTINATION PORTS'])
                    writer.writerow(['Rank', 'Port', 'Service', 'Packet Count', 'Percentage'])
                    for rank, (port, count) in enumerate(top_ports, 1):
                        service_name = common_services.get(port, "Unknown/Ephemeral")
                        percentage = (count / self.packet_count) * 100
                        writer.writerow([rank, port, service_name, count, f'{percentage:.1f}%'])
                    writer.writerow([])
                    
                    # Top 5 IPs
                    writer.writerow(['TOP 5 DESTINATION IP ADDRESSES'])
                    writer.writerow(['Rank', 'IP Address', 'Domain Name', 'Packet Count', 'Percentage'])
                    for rank, (ip, count) in enumerate(top_ips, 1):
                        domain = self.resolve_ip_to_domain(ip)
                        percentage = (count / self.packet_count) * 100
                        writer.writerow([rank, ip, domain if domain != ip else 'N/A', count, f'{percentage:.1f}%'])
                    
            elif file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    # Prepare top ports data
                    ports_data = []
                    for rank, (port, count) in enumerate(top_ports, 1):
                        service_name = common_services.get(port, "Unknown/Ephemeral")
                        percentage = (count / self.packet_count) * 100
                        ports_data.append({
                            'rank': rank,
                            'port': port,
                            'service': service_name,
                            'packet_count': count,
                            'percentage': round(percentage, 1)
                        })
                    
                    # Prepare top IPs data
                    ips_data = []
                    for rank, (ip, count) in enumerate(top_ips, 1):
                        domain = self.resolve_ip_to_domain(ip)
                        percentage = (count / self.packet_count) * 100
                        ips_data.append({
                            'rank': rank,
                            'ip_address': ip,
                            'domain_name': domain if domain != ip else None,
                            'packet_count': count,
                            'percentage': round(percentage, 1)
                        })
                    
                    # Build summary JSON
                    summary_data = {
                        'traffic_analysis_summary': {
                            'capture_session': {
                                'start_time': self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else None,
                                'end_time': self.end_time.strftime('%Y-%m-%d %H:%M:%S') if self.end_time else None,
                                'duration_seconds': (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else None,
                                'total_packets': self.packet_count,
                                'unique_destination_ips': len(self.destination_ips),
                                'unique_destination_ports': len(self.destination_ports)
                            },
                            'top_5_destination_ports': ports_data,
                            'top_5_destination_ips': ips_data
                        }
                    }
                    json.dump(summary_data, f, indent=2)
                    
            else:  # TXT
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("=" * 100 + "\n")
                    f.write("TRAFFIC ANALYSIS SUMMARY - RECONNAISSANCE REPORT\n")
                    f.write("=" * 100 + "\n\n")
                    
                    # Capture session info
                    f.write("CAPTURE SESSION INFORMATION:\n")
                    f.write("-" * 100 + "\n")
                    if self.start_time:
                        f.write(f"Capture Started:  {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                    if self.end_time:
                        f.write(f"Capture Ended:    {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        if self.start_time:
                            duration = (self.end_time - self.start_time).total_seconds()
                            f.write(f"Duration:         {duration:.2f} seconds\n")
                    f.write(f"Total Packets:    {self.packet_count}\n")
                    f.write(f"Unique Dest IPs:  {len(self.destination_ips)}\n")
                    f.write(f"Unique Dest Ports: {len(self.destination_ports)}\n\n")
                    
                    # Top 5 ports
                    f.write("=" * 100 + "\n")
                    f.write("TOP 5 DESTINATION PORTS (Most Accessed Services):\n")
                    f.write("-" * 100 + "\n")
                    for rank, (port, count) in enumerate(top_ports, 1):
                        service_name = common_services.get(port, "Unknown/Ephemeral")
                        percentage = (count / self.packet_count) * 100
                        f.write(f"  #{rank}  Port {port:5} ({service_name:17}) - {count:4} packets ({percentage:5.1f}%)\n")
                    f.write("\n")
                    
                    # Top 5 IPs
                    f.write("=" * 100 + "\n")
                    f.write("TOP 5 DESTINATION IP ADDRESSES (Most Contacted Servers/Websites):\n")
                    f.write("-" * 100 + "\n")
                    for rank, (ip, count) in enumerate(top_ips, 1):
                        domain = self.resolve_ip_to_domain(ip)
                        percentage = (count / self.packet_count) * 100
                        if domain != ip:
                            f.write(f"  #{rank}  {ip:15} → {domain:40} - {count:4} packets ({percentage:5.1f}%)\n")
                        else:
                            f.write(f"  #{rank}  {ip:15} (No domain name found)          - {count:4} packets ({percentage:5.1f}%)\n")
                    f.write("\n")
                    
                    # Insights
                    f.write("=" * 100 + "\n")
                    f.write("KEY INSIGHTS:\n")
                    f.write("-" * 100 + "\n")
                    
                    if 443 in self.destination_ports:
                        https_count = self.destination_ports[443]
                        https_percent = (https_count / self.packet_count) * 100
                        f.write(f"  ✓ {https_percent:.1f}% of traffic uses HTTPS (Port 443) - Good security practice!\n")
                    
                    if 80 in self.destination_ports:
                        http_count = self.destination_ports[80]
                        http_percent = (http_count / self.packet_count) * 100
                        f.write(f"  ⚠ {http_percent:.1f}% of traffic uses unencrypted HTTP (Port 80) - Consider using HTTPS\n")
                    
                    ephemeral_count = sum(count for port, count in self.destination_ports.items() if port >= 49152)
                    if ephemeral_count > 0:
                        ephemeral_percent = (ephemeral_count / self.packet_count) * 100
                        f.write(f"  ℹ {ephemeral_percent:.1f}% uses ephemeral ports (49152-65535) - Normal for client connections\n")
                    
                    if len(self.destination_ips) > 20:
                        f.write(f"  ℹ High connection diversity ({len(self.destination_ips)} unique IPs) - Active web browsing/multi-service usage\n")
                    elif len(self.destination_ips) < 5:
                        f.write(f"  ℹ Low connection diversity ({len(self.destination_ips)} unique IPs) - Focused activity on few services\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
            
            messagebox.showinfo("Success", f"Traffic analysis summary exported to:\n{file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export summary:\n{str(e)}")
    
    def validate_inputs(self, port_str, capture_mode, capture_value_str):
        """
        Validate user inputs for port and capture mode value.
        Returns: (success, error_message, port, capture_value)
        """
        port = None

        # Validate port if provided
        if port_str and port_str.strip():
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    return False, "Error: Port must be between 1 and 65535.", None, None
            except ValueError:
                return False, "Error: Port must be a valid integer.", None, None

        # Validate capture value
        try:
            capture_value = int(capture_value_str)
        except ValueError:
            if capture_mode == "Max Packets":
                return False, "Error: Packet limit must be a valid integer.", None, None
            else:
                return False, "Error: Timeout must be a valid integer.", None, None

        if capture_mode == "Max Packets":
            if capture_value < 1 or capture_value > 10000:
                return False, "Error: Packet limit must be between 1 and 10000.", None, None
        else:  # Timeout (second/s)
            if capture_value < 1 or capture_value > 3600:
                return False, "Error: Timeout must be between 1 and 3600 seconds.", None, None

        return True, "", port, capture_value
    
    def build_filter_string(self, protocol, port):
        """
        Build a BPF (Berkeley Packet Filter) string based on user selections.
        
        BPF filters are used by packet capture libraries to filter traffic at the kernel level,
        which is more efficient than filtering in user space. The filter syntax follows
        the pcap-filter standard used by tools like tcpdump and Wireshark.
        
        Args:
            protocol (str): Protocol to filter ('tcp', 'udp', 'icmp', or 'all')
            port (int or None): Optional port number to filter
        
        Returns:
            str or None: BPF filter string (e.g., "tcp and port 80") or None for no filter
        
        Examples:
            - protocol='tcp', port=80 → "tcp and port 80"
            - protocol='udp', port=None → "udp"
            - protocol='all', port=443 → "port 443"
            - protocol='all', port=None → None (captures all traffic)
        """
        filters = []
        
        # FILTER APPLICATION STEP 1: Add protocol filter
        # If user selected a specific protocol (not 'all'), add it to the filter list.
        # This restricts capture to only packets of that protocol type.
        if protocol != "all":
            filters.append(protocol)
        
        # FILTER APPLICATION STEP 2: Add port filter
        # Port filtering only makes sense for TCP/UDP (which have ports).
        # ICMP doesn't use ports, so we only add port filter for TCP/UDP or 'all'.
        if port:
            if protocol == "tcp" or protocol == "udp":
                # For specific protocols, add port filter
                # This captures packets where either source or destination port matches
                filters.append(f"port {port}")
            elif protocol == "all":
                # For 'all' protocols, still filter by port (captures TCP/UDP with that port)
                filters.append(f"port {port}")
        
        # FILTER APPLICATION STEP 3: Combine filters with 'and' operator
        # Multiple conditions are joined with 'and' to create a compound filter.
        # Example: ['tcp', 'port 80'] becomes "tcp and port 80"
        # If no filters were added, return None (meaning capture all traffic)
        return " and ".join(filters) if filters else None
    
    def process_packet(self, packet):
        """
        Process and format a captured packet for display.
        
        This function is called by Scapy's sniff() function for each captured packet.
        It extracts relevant information from the packet's protocol layers and formats
        it into a human-readable string for display.
        
        PACKET PROCESSING WORKFLOW:
        1. Check if capture is still active
        2. Extract timestamp when packet was processed
        3. Parse packet layers (IP, TCP/UDP/ICMP)
        4. Extract source/destination IPs and ports
        5. Format and display the packet information
        
        Args:
            packet: Scapy packet object containing multiple protocol layers
        
        Scapy Packet Structure:
            Packets in Scapy are layered objects. For example, a typical HTTP packet has:
            [Ethernet] / [IP] / [TCP] / [HTTP]
            We can check if a layer exists using: if TCP in packet
            We can access layer data using: packet[TCP].sport
        """
        # PROCESSING STEP 1: Check if capture is still active
        # If user stopped capture, immediately return without processing
        if not self.capturing:
            return
        
        try:
            # PROCESSING STEP 2: Get current timestamp
            # Format: YYYY-MM-DD HH:MM:SS.mmm (year-month-day hours:minutes:seconds.milliseconds)
            # [:-3] removes the last 3 microsecond digits to show only milliseconds            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            
            # PROCESSING STEP 3: Initialize packet detail variables
            # These will store extracted information, defaulting to "N/A" if not found
            protocol = "Unknown"
            src_ip = "N/A"
            dst_ip = "N/A"
            src_port = "N/A"
            dst_port = "N/A"
            info = ""

            # Ignore packets without IP layer
            if not packet.haslayer(IP):
                return

            # Ignore packets without TCP, UDP, or ICMP
            if not (packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP)):
                return
            
            if IP in packet:
                # Extract source and destination IP addresses from IP layer
                # These show who sent the packet and where it's going
                src_ip = packet[IP].src   # Source IP (e.g., "192.168.1.100")
                dst_ip = packet[IP].dst   # Destination IP (e.g., "142.250.185.46")
                
                
                if TCP in packet:
                    # TCP (Transmission Control Protocol) - connection-oriented protocol
                    protocol = "TCP"
                    src_port = packet[TCP].sport  # Source port (where packet came from)
                    dst_port = packet[TCP].dport  # Destination port (where packet is going)
                    
                    # Extract TCP flags (SYN, ACK, FIN, etc.) for connection analysis
                    # Flags show the state of TCP connections (establishing, data transfer, closing)
                    flags = packet[TCP].flags
                    info = f"Flags: {flags}"
                    
                elif UDP in packet:
                    # UDP (User Datagram Protocol) - connectionless protocol
                    # Used for DNS queries, streaming, gaming, etc.
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    info = "UDP datagram"
                    
                elif ICMP in packet:
                    # ICMP (Internet Control Message Protocol) - used for diagnostics
                    # Examples: ping requests/replies, destination unreachable messages
                    protocol = "ICMP"
                    icmp_type = packet[ICMP].type  # Message type (e.g., 8=echo request, 0=echo reply)
                    icmp_code = packet[ICMP].code  # Sub-type code providing more detail
                    info = f"Type: {icmp_type}, Code: {icmp_code}"
                else:
                    # Other IP protocols (e.g., GRE, ESP, etc.)
                    # Display protocol number from IP header
                    protocol = f"IP/{packet[IP].proto}"
            
            # PROCESSING STEP 6: Format output for display
            # Create a structured, aligned output line with all extracted information
            # Format: [timestamp] protocol | SRC: ip:port | DST: ip:port | additional_info
            output_line = f"[{timestamp}] {protocol:6} | SRC: {src_ip:15}:{str(src_port):5} | DST: {dst_ip:15}:{str(dst_port):5}"
            if info:
                output_line += f" | {info}"
            
            # ====================================================================
            # PROCESSING STEP 7: Display formatted packet with color coding
            # ====================================================================
            # Determine color tag based on protocol for visual differentiation
            # Color scheme:
            # - TCP:  Blue (most common - web browsing, file transfers)
            # - UDP:  Purple (streaming, DNS, gaming)
            # - ICMP: Orange (diagnostics, ping)
            tag = None
            if protocol == "TCP":
                tag = "tcp"      # Blue - connection-oriented, reliable
            elif protocol == "UDP":
                tag = "udp"      # Purple - connectionless, fast
            elif protocol == "ICMP":
                tag = "icmp"     # Orange - control/diagnostic messages
            
            # Display the formatted packet information in the GUI
            # Tag determines text color for easy visual protocol identification
            self.display_output(output_line, tag)
            self.packet_count += 1  # Increment global packet counter
            
            # ====================================================================
            # DATA STORAGE: Store packet data for export functionality
            # ====================================================================
            # Store in structured format: [timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info]
            # This data can later be exported to CSV/JSON/TXT for analysis
            self.capture_data.append([timestamp, protocol, src_ip, src_port, dst_ip, dst_port, info])
            
            # Store detected pors for dropdown filtering
            if isinstance(src_port, int):
                self.detected_ports_set.add(src_port)
            if isinstance(dst_port, int):
                self.detected_ports_set.add(dst_port)

            # Refresh dropdown with new ports
            self.update_detected_port_dropdown()

            # ====================================================================
            # PROCESSING STEP 8: Reconnaissance data collection
            # ====================================================================
            # Perform information gathering by tracking traffic patterns
            # This intelligence identifies:
            # - What services are being accessed (port analysis)
            # - What servers are being contacted (IP analysis)
            # - Potential security concerns (unusual ports/destinations)
            
            if dst_port != "N/A" and isinstance(dst_port, int):
                self.destination_ports[dst_port] = self.destination_ports.get(dst_port, 0) + 1

                # Track known ports (0-1023)
                if 0 <= dst_port <= 1023:
                    self.known_ports[dst_port] = self.known_ports.get(dst_port, 0) + 1

                # Track ephemeral ports (49152-65535)
                elif 49152 <= dst_port <= 65535:
                    self.ephemeral_ports[dst_port] = self.ephemeral_ports.get(dst_port, 0) + 1
            
            if dst_ip != "N/A":
                # Track destination IPs to identify frequently contacted servers
                # Example insights:
                # - Repeated connections to same IP → Active service usage
                # - Many unique IPs → Diverse web browsing
                # - Suspicious IPs → Potential malware C&C communication
                self.destination_ips[dst_ip] = self.destination_ips.get(dst_ip, 0) + 1
            
            # PROCESSING STEP 9: Extract domain names from packet payload
            # This provides much more accurate domain resolution than reverse DNS
            if TCP in packet and Raw in packet:
                # Extract SNI from TLS Client Hello (for HTTPS traffic)
                if dst_port == 443 or dst_port == 8443:  # HTTPS ports
                    domain = self.extract_sni_from_packet(packet)
                    if domain and dst_ip != "N/A":
                        self.ip_to_domain_from_traffic[dst_ip] = domain
                
                # Extract Host header from HTTP requests (for HTTP traffic)
                elif dst_port == 80 or dst_port == 8080:  # HTTP ports
                    domain = self.extract_http_host(packet)
                    if domain and dst_ip != "N/A":
                        self.ip_to_domain_from_traffic[dst_ip] = domain
            
        except Exception as e:
            # Silently skip malformed or corrupted packets
            # This prevents the analyzer from crashing on unexpected packet formats
            pass
    
    def capture_packets(self, filter_str, packet_limit, timeout_sec):
        """
        Capture network packets using Scapy's sniff() function.
        
        This is the main packet capture function that interfaces with Scapy's sniffing
        capabilities. It captures live network traffic and processes each packet in real-time.
        This function runs in a separate thread to prevent blocking the GUI.
        
        THE SNIFFING PROCESS - How it works:
        
        1. INITIALIZATION: Set up capture parameters and display status
        2. SNIFFING: Call Scapy's sniff() function which:
           - Opens a network interface in promiscuous mode (captures all traffic)
           - Applies BPF filter at the kernel level (very efficient)
           - Captures packets from the network interface
           - For each captured packet, calls the callback function (process_packet)
        3. PROCESSING: Each packet is immediately processed and displayed
        4. TERMINATION: Stops when count is reached or user stops capture
        5. CLEANUP: Display summary and re-enable UI controls
        
        Args:
            filter_str (str or None): BPF filter string to apply (e.g., "tcp and port 80")
            packet_limit (int): Maximum number of packets to capture
        
        Threading:
            This function runs in a background thread (daemon) so the GUI remains responsive.
            The capturing flag controls when to stop.
        """
        try:
            # SNIFFING STEP 1: Display capture initialization information
            self.display_output("=" * 100, "header")
            self.display_output(f"Capture started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", "header")
            self.display_output(f"Capture Protocol: {self.captured_protocol.upper() if self.captured_protocol else 'ALL'}", "info")
            self.display_output(f"Filter: {filter_str if filter_str else 'None (capturing all traffic)'}", "info")
            
            if packet_limit is not None:
                self.display_output(f"Max packets: {packet_limit}", "info")
            if timeout_sec is not None:
                self.display_output(f"Timeout: {timeout_sec} seconds", "info")

            if self.captured_protocol and self.captured_protocol != "all":
                self.display_output(f"ℹ Tip: Results filter works best with '{self.captured_protocol.upper()} Only' or 'All' options", "info")
            self.display_output("=" * 100, "header")
            
            # SNIFFING STEP 2: Start the Scapy packet sniffer
            # This is the core of the network traffic analyzer.
            # Scapy's sniff() function captures packets from the network interface.
            #
            # HOW SCAPY SNIFFING WORKS:
            # - On Windows: Uses Npcap/WinPcap to access network interfaces
            # - On Linux: Uses libpcap or native socket interfaces
            # - Requires admin/root privileges to put interface in promiscuous mode
            # - Promiscuous mode allows capturing all packets, not just those destined for this computer
            #
            # SNIFF() PARAMETERS EXPLAINED:
            # https://scapy.readthedocs.io/en/latest/usage.html#advanced-sniffing-sniffing-sessions                   

            # Build the arguments for sniff() based on user input and capture settings
            sniff_kwargs = {
                "prn": self.process_packet,
                "filter": filter_str,
                "store": 0,
                "stop_filter": lambda x: not self.capturing
            }

            # Add count and timeout parameters only if they are specified by the user
            if packet_limit is not None:
                sniff_kwargs["count"] = packet_limit

            if timeout_sec is not None:
                sniff_kwargs["timeout"] = timeout_sec

            sniff(**sniff_kwargs)       # Start packet capture with specified parameters. This call blocks until capture ends.
            
            # SNIFFING STEP 3: Display capture completion summary
            # After sniff() returns, display results based on how capture ended
            end_time = datetime.now()
            self.end_time = end_time  # Store for export
            duration = end_time - self.start_time
            duration_seconds = duration.total_seconds()

            header_lines = []
            header_lines.append("=" * 100)
            header_lines.append(f"Capture started at: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
            header_lines.append(f"Capture Protocol: {self.captured_protocol.upper() if self.captured_protocol else 'ALL'}")
            header_lines.append(f"Filter: {filter_str if filter_str else 'None (capturing all traffic)'}")

            if packet_limit is not None:
                header_lines.append(f"Max packets: {packet_limit}")
            if timeout_sec is not None:
                header_lines.append(f"Timeout: {timeout_sec} seconds")

            if self.captured_protocol and self.captured_protocol != "all":
                header_lines.append(
                    f"ℹ Tip: Results filter works best with '{self.captured_protocol.upper()} Only' or 'All' options"
                )

            header_lines.append("=" * 100)

            self.capture_session_header = "\n".join(header_lines)
            
            if self.capturing:
                self.capture_completion_summary = (
                    "=" * 100 + "\n"
                    f"Capture completed at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Duration: {duration_seconds:.2f} seconds\n"
                    f"Total packets captured: {self.packet_count}\n"
                    + "=" * 100
                )
            else:
                self.capture_completion_summary = (
                    "=" * 100 + "\n"
                    f"Capture stopped by user at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Duration: {duration_seconds:.2f} seconds\n"
                    f"Packets captured: {self.packet_count}\n"
                    + "=" * 100
                )
            
            # SNIFFING STEP 4: Perform reconnaissance analysis and display insights
            # Analyze captured data to provide actionable intelligence
            if self.packet_count > 0:
                self.apply_filter()
            
        except PermissionError:
            # Raised when program doesn't have sufficient privileges to capture packets
            # Network interfaces require administrator/root access for promiscuous mode
            self.display_output("Error: Permission denied. Please run the program as administrator/root.", "info")
        except OSError as e:
            # General OS-level errors (interface not found, driver issues, etc.)
            self.display_output(f"Error: {str(e)}", "info")
            self.display_output("Hint: You may need administrator/root privileges to capture packets.", "info")
        except Exception as e:
            # Catch any other unexpected errors during capture
            self.display_output(f"Error during capture: {str(e)}", "info")
        finally:
            # SNIFFING STEP 5: Cleanup - always re-enable the start button
            # This executes regardless of how the function exits (success or error)
            self.enable_start_button()

        if hasattr(self, "parent_gui"):
            self.parent_gui.status_label.config(
                text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Traffic capture complete"
            )

        # END OF CAPTURE FUNCTION - The GUI is now responsive again, and user can start a new capture or export results.
        if hasattr(self, "parent_gui"):
            summary_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.parent_gui.latest_traffic_analyzer_summary = (
                f"Time: {summary_time}\n"
                f"Packets: {self.packet_count}\n"
                f"Unique Destination IPs: {len(self.destination_ips)}\n"
                f"Unique Destination Ports: {len(self.destination_ports)}"
            )
            self.parent_gui.update_security_dashboard()
    
    def extract_sni_from_packet(self, packet):
        """
        Extract Server Name Indication (SNI) from TLS Client Hello packets.
        
        SNI is an extension to TLS that allows clients to specify which hostname
        they are attempting to connect to. This is sent in plaintext during the
        TLS handshake, making it possible to extract the domain name even from
        encrypted HTTPS traffic.
        
        Args:
            packet: Scapy packet object
        
        Returns:
            str or None: Extracted domain name or None if not found
        """
        try:
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                
                # TLS Client Hello starts with: 0x16 (Handshake) 0x03 0x01/0x03 (TLS version)
                if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
                    # Look for SNI extension (type 0x00 0x00)
                    # SNI is in the extensions section of Client Hello
                    pos = payload.find(b'\x00\x00')  # Server Name extension type
                    
                    if pos != -1 and pos + 9 < len(payload):
                        # Skip to the server name (after extension header)
                        # Format: type(2) + length(2) + list_length(2) + type(1) + name_length(2) + name
                        try:
                            # Find the actual hostname in the SNI extension
                            # Look for patterns that indicate SNI hostname
                            for i in range(pos, min(pos + 200, len(payload) - 10)):
                                if payload[i] == 0x00 and i + 3 < len(payload):
                                    name_length = (payload[i + 1] << 8) | payload[i + 2]
                                    if 3 < name_length < 100:  # Reasonable domain length
                                        start = i + 3
                                        end = start + name_length
                                        if end <= len(payload):
                                            try:
                                                hostname = payload[start:end].decode('utf-8', errors='ignore')
                                                # Validate it looks like a domain name
                                                if '.' in hostname and hostname.replace('.', '').replace('-', '').replace('_', '').isalnum():
                                                    return hostname
                                            except:
                                                continue
                        except:
                            pass
        except:
            pass
        return None
    
    def extract_http_host(self, packet):
        """
        Extract Host header from HTTP requests.
        
        HTTP requests include a Host header that specifies the domain name
        being accessed. This is sent in plaintext, making it easy to extract.
        
        Args:
            packet: Scapy packet object
        
        Returns:
            str or None: Extracted domain name or None if not found
        """
        try:
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                
                # Look for HTTP request methods (GET, POST, etc.)
                if payload.startswith(b'GET ') or payload.startswith(b'POST ') or \
                   payload.startswith(b'HEAD ') or payload.startswith(b'PUT '):
                    
                    # Try to decode as UTF-8
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        
                        # Look for Host header
                        for line in payload_str.split('\r\n'):
                            if line.lower().startswith('host:'):
                                # Extract hostname
                                host = line.split(':', 1)[1].strip()
                                # Remove port if present
                                if ':' in host:
                                    host = host.split(':')[0]
                                return host
                    except:
                        pass
        except:
            pass
        return None
    
    def resolve_ip_to_domain(self, ip_address):
        """
        Resolve IP address to domain name using multiple strategies.
        
        This function uses a multi-layered approach to identify domain names:
        1. Check traffic-extracted domains (SNI from TLS, Host from HTTP) - MOST ACCURATE
        2. Check reverse DNS cache
        3. Perform reverse DNS lookup
        
        Traffic-extracted domains are more reliable because they show the actual
        domain the user intended to access, not just what reverse DNS reports.
        
        Args:
            ip_address (str): IP address to resolve
        
        Returns:
            str: Domain name or original IP if resolution fails
        
        Examples:
            - 172.217.14.206 → google.com (from SNI)
            - 151.101.1.69 → reddit.com (from HTTP Host)
            - Private/local IPs remain unchanged or show hostname
        """
        # STRATEGY 1: Check if we extracted domain from packet payload (SNI or HTTP Host)
        # This is the most accurate method as it shows what the user actually requested
        if ip_address in self.ip_to_domain_from_traffic:
            return self.ip_to_domain_from_traffic[ip_address]
        
        # STRATEGY 2: Check cache for previous reverse DNS results
        if ip_address in self.ip_to_domain:
            return self.ip_to_domain[ip_address]
        
        # STRATEGY 3: Perform reverse DNS lookup
        try:
            # Set a timeout to avoid hanging on slow DNS servers
            socket.setdefaulttimeout(2)
            # gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            
            # Clean up the hostname (remove trailing dots)
            hostname = hostname.rstrip('.')
            
            # Cache the result for future use
            self.ip_to_domain[ip_address] = hostname
            return hostname
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            # DNS lookup failed - cache the IP to avoid repeated lookups
            # This is common for:
            # - Private IP addresses (192.168.x.x, 10.x.x.x)
            # - IPs without reverse DNS records
            # - Network connectivity issues
            self.ip_to_domain[ip_address] = ip_address
            return ip_address
        finally:
            # Reset timeout to default
            socket.setdefaulttimeout(None)

    def render_capture_session_header(self):
        """Render the saved capture session header with consistent colors."""
        if not self.capture_session_header:
            return

        header_lines = self.capture_session_header.split("\n")

        for line in header_lines:
            if line.startswith("="):
                self.output_text.insert(tk.END, line + "\n", "header")
            elif line.startswith("Capture started at:"):
                self.output_text.insert(tk.END, line + "\n", "header")
            else:
                self.output_text.insert(tk.END, line + "\n", "info")

        self.output_text.insert(tk.END, "\n")
    
    def display_traffic_summary(self, summary_only=False):
        """
        Display reconnaissance summary showing Top destination ports and IPs.

        summary_only=False  -> append summary below captured packets
        summary_only=True   -> clear box and show only the summary view
        """
        if summary_only:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)

            if self.capture_session_header:
                header_lines = self.capture_session_header.split("\n")
                for line in header_lines:
                    if line.startswith("="):
                        self.output_text.insert(tk.END, line + "\n", "header")
                    elif line.startswith("Capture started at:"):
                        self.output_text.insert(tk.END, line + "\n", "header")
                    else:
                        self.output_text.insert(tk.END, line + "\n", "info")
                self.output_text.insert(tk.END, "\n")

        # RECONNAISSANCE SUMMARY HEADER
        self.output_text.insert(tk.END, "=" * 100 + "\n", "summary")
        self.output_text.insert(
            tk.END,
            "RECONNAISSANCE SUMMARY - TRAFFIC ANALYSIS & INFORMATION GATHERING\n",
            "summary"
        )
        self.output_text.insert(tk.END, "=" * 100 + "\n", "summary")

        # TOP KNOWN PORTS
        self.output_text.insert(
            tk.END,
            "\n🎯 TOP KNOWN DESTINATION PORTS (Common Service Ports):\n",
            "summary"
        )
        self.output_text.insert(tk.END, "-" * 100 + "\n", "summary")

        if self.known_ports:
            top_known_ports = sorted(self.known_ports.items(), key=lambda x: x[1], reverse=True)[:5]

            for rank, (port, count) in enumerate(top_known_ports, 1):
                service_name = COMMON_SERVICES.get(port, "Known/Other")
                percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0

                self.output_text.insert(
                    tk.END,
                    f"  #{rank}  Port {port:5} ({service_name:17}) - {count:4} packets ({percentage:5.1f}%)\n",
                    "summary"
                )
        else:
            self.output_text.insert(tk.END, "  No known destination ports captured.\n", "summary")

        # TOP EPHEMERAL PORTS
        self.output_text.insert(
            tk.END,
            "\n🎯 TOP EPHEMERAL DESTINATION PORTS (High Temporary Ports):\n",
            "summary"
        )
        self.output_text.insert(tk.END, "-" * 100 + "\n", "summary")

        if self.ephemeral_ports:
            top_ephemeral_ports = sorted(self.ephemeral_ports.items(), key=lambda x: x[1], reverse=True)[:5]

            for rank, (port, count) in enumerate(top_ephemeral_ports, 1):
                percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0

                self.output_text.insert(
                    tk.END,
                    f"  #{rank}  Port {port:5} (Ephemeral)        - {count:4} packets ({percentage:5.1f}%)\n",
                    "summary"
                )
        else:
            self.output_text.insert(tk.END, "  No ephemeral destination ports captured.\n", "summary")

        # TOP 5 DESTINATION IP ADDRESSES
        self.output_text.insert(
            tk.END,
            "\n🌐 TOP 5 DESTINATION IP ADDRESSES (Most Contacted Servers/Websites):\n",
            "summary"
        )
        self.output_text.insert(tk.END, "-" * 100 + "\n", "summary")

        if self.destination_ips:
            top_ips = sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True)[:5]

            for rank, (ip, count) in enumerate(top_ips, 1):
                percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
                domain = self.resolve_ip_to_domain(ip)

                # clickable IP lines go HERE
                self.insert_clickable_ip_line(rank, ip, domain, count, percentage)
        else:
            self.output_text.insert(tk.END, "  No destination IP data collected.\n", "summary")

        # OVERALL STATISTICS
        self.output_text.insert(tk.END, "\n📊 OVERALL STATISTICS:\n", "summary")
        self.output_text.insert(tk.END, "-" * 100 + "\n", "summary")
        self.output_text.insert(
            tk.END,
            f"  Capture Protocol Filter: {self.captured_protocol.upper() if self.captured_protocol else 'ALL'}\n",
            "summary"
        )
        self.output_text.insert(
            tk.END,
            f"  Total unique destination ports contacted: {len(self.destination_ports)}\n",
            "summary"
        )
        self.output_text.insert(
            tk.END,
            f"  Total unique destination IPs contacted: {len(self.destination_ips)}\n",
            "summary"
        )
        self.output_text.insert(
            tk.END,
            f"  Total packets analyzed: {self.packet_count}\n",
            "summary"
        )

        # INSIGHTS
        self.output_text.insert(tk.END, "\n💡 INSIGHTS:\n", "summary")
        self.output_text.insert(tk.END, "-" * 100 + "\n", "summary")

        if 443 in self.destination_ports:
            https_count = self.destination_ports[443]
            https_percent = (https_count / self.packet_count) * 100 if self.packet_count > 0 else 0
            self.output_text.insert(
                tk.END,
                f"  ✓ {https_percent:.1f}% of traffic uses HTTPS (Port 443) - Good security practice!\n",
                "summary"
            )

        if 80 in self.destination_ports:
            http_count = self.destination_ports[80]
            http_percent = (http_count / self.packet_count) * 100 if self.packet_count > 0 else 0
            self.output_text.insert(
                tk.END,
                f"  ⚠ {http_percent:.1f}% of traffic uses unencrypted HTTP (Port 80) - Consider using HTTPS\n",
                "summary"
            )

        ephemeral_count = sum(count for port, count in self.destination_ports.items() if port >= 49152)
        if ephemeral_count > 0:
            ephemeral_percent = (ephemeral_count / self.packet_count) * 100 if self.packet_count > 0 else 0
            self.output_text.insert(
                tk.END,
                f"  ℹ {ephemeral_percent:.1f}% of traffic uses ephemeral ports (49152-65535) - These are temporary high-number ports commonly used by clients\n",
                "summary"
            )

        if len(self.destination_ips) > 20:
            self.output_text.insert(
                tk.END,
                f"  ℹ High connection diversity ({len(self.destination_ips)} unique IPs) - Active web browsing/multi-service usage\n",
                "summary"
            )
        elif len(self.destination_ips) < 5:
            self.output_text.insert(
                tk.END,
                f"  ℹ Low connection diversity ({len(self.destination_ips)} unique IPs) - Focused activity on few services\n",
                "summary"
            )

        self.output_text.insert(tk.END, "=" * 100 + "\n", "summary")
        self.output_text.config(state=tk.DISABLED)

    def start_capture(self):
        """Handle the start capture button click - Entry point for network traffic analysis
        
        Workflow:
        1. Collect and validate capture settings (protocol, port filter, packet limit)
        2. Build BPF (Berkeley Packet Filter) string for kernel-level filtering
        3. Clear previous results
        4. Launch capture in background thread
        5. Update UI elements
        
        Threading Strategy:
        Packet capture MUST run in a separate thread because:
        - Capture can run for extended periods (minutes to hours)
        - Packets arrive continuously and need real-time processing
        - Blocking main thread would freeze GUI completely
        - Users need ability to stop capture at any time
        
        Security Note:
        Packet capture requires administrator/root privileges to access
        network interfaces in promiscuous mode.
        """
        # Prevent multiple simultaneous captures or capture without Scapy
        if self.capturing or not SCAPY_AVAILABLE:
            return
        
        if hasattr(self, "parent_gui"):
            self.parent_gui.status_label.config(
                text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Capturing traffic"
            )
        
        # ========================================================================
        # PHASE 1: INPUT COLLECTION
        # ========================================================================
        # Collect capture configuration from GUI elements
        protocol = self.protocol_var.get()              # Protocol filter: tcp/udp/icmp/all
        port_str = self.port_entry.get().strip()        # Optional port filter (e.g., "80", "443")
        capture_mode = self.capture_mode.get()          # Capture mode: Max Packet ("packet_limit") or Timeout(s) ("time_limit")
        capture_value_str = self.capture_mode_value_entry.get().strip() # Value for capture mode (packet limit or time limit)

        
        # ========================================================================
        # PHASE 2: INPUT VALIDATION
        # ========================================================================
        # Validate capture settings before starting
        # Checks:
        # - Port number is valid (1-65535) if specified
        # - Packet limit is reasonable (1-10000)
        valid, error_msg, port, capture_value = self.validate_inputs(
            port_str, capture_mode, capture_value_str
        )
                        
        if not valid:
            self.display_output(error_msg, "info")
            messagebox.showerror("Input Error", error_msg)
            return
        
        # Decide whether capture_value is packet limit or timeout
        if capture_mode == "Max Packets":
            packet_limit = capture_value
            timeout_sec = None
        else:
            packet_limit = None
            timeout_sec = capture_value
        
        # ========================================================================
        # PHASE 3: BPF FILTER SETUP
        # ========================================================================
        # Build Berkeley Packet Filter (BPF) string for efficient packet filtering
        # BPF filtering happens at kernel level, which is MUCH more efficient than
        # filtering in user space. Rejected packets never reach our application.
        #
        # Examples:
        # - "tcp and port 80" - Only HTTP traffic
        # - "udp and port 53" - Only DNS queries
        # - "tcp" - All TCP traffic
        # - None - Capture everything
        filter_str = self.build_filter_string(protocol, port)
        
        # ========================================================================
        # PHASE 4: PREPARATION
        # ========================================================================
        # Clear previous capture results to avoid confusion
        self.clear_results()
        
        # Store the protocol filter for later validation
        # This ensures filter buttons match what was actually captured
        self.captured_protocol = protocol
        
        # Record start time for duration calculation and timestamp metadata
        self.start_time = datetime.now()
        
        # Set capturing flag and update UI state
        self.capturing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # ========================================================================
        # PHASE 5: MULTI-THREADING - Launch capture in background
        # ========================================================================
        # Create and start a new thread for packet capture
        # Why separate thread?
        # 1. Packet capture blocks waiting for network traffic
        # 2. Processing each packet takes time (parsing layers, DNS lookups)
        # 3. Capture can run for minutes/hours
        # 4. GUI must remain responsive for real-time display and stop button
        #
        # daemon=True: Thread terminates automatically when application closes
        self.capture_thread = threading.Thread(
            target=self.capture_packets,        # Function to run in thread
            args=(filter_str, packet_limit, timeout_sec),    # Pass filter string and limit
            daemon=True                         # Auto-terminate with main program
        )
        self.capture_thread.start()    

    def stop_capture(self):
        """Handle the stop capture button click"""
        self.capturing = False
        self.display_output("\nStopping capture...")

        if hasattr(self, "parent_gui"):
            self.parent_gui.status_label.config(
                text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Capture stopped"
            )

        self.enable_start_button()
    
    def enable_start_button(self):
        """Safely re-enable the start button after capture completes."""
        self.parent_frame.after(0, self._enable_start_button_gui)

    def _enable_start_button_gui(self):
        """Actual GUI update for capture button state."""
        self.capturing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
               
        
# ==================== INTEGRATED SECURITY SUITE GUI ====================
class SecuritySuiteGUI:
    """
    Main GUI application for the integrated Security Suite.

    Purpose:
        Provides a unified graphical interface for all security modules in the project.

    Main responsibilities:
        - Build the main application window and tab layout
        - Connect all security modules into one interface
        - Manage cross-module integration and dashboard summaries
        - Handle user interaction and navigation between tabs
    """

    def __init__(self, root):
        """
        Initialize the main GUI application with all components.
        
        Args:
            root: Tkinter root window
        """
        self.root = root
        self.root.title("Security Suite")
        
        # Set window to fullscreen
        # self.root.state('zoomed')  # Windows fullscreen
        self.root.geometry("1240x975")        
        self.root.resizable(True, True)
        self.root.minsize(1240, 820)
        
        # Modern color scheme with module-specific colors
        self.bg_color = "#f5f6fa"
        self.header_bg = "#000000"  # Black header
        self.header_accent = "#ffffff"  # White accent bar
        
        # Module-specific colors
        self.teal_color = "#1abc9c"  # Teal for Password Strength
        self.purple_color = "#9b59b6"  # Purple for Generator
        self.orange_color = "#e67e22"  # Orange for Input Validation
        self.blue_color = "#3498db"  # Blue for Port Scanner
        self.red_color = "#e74c3c"  # Red for Traffic Analyzer
        
        # Status colors
        self.success_color = "#27ae60"
        self.warning_color = "#f39c12"
        self.danger_color = "#e74c3c"
        self.card_bg = "#ffffff"
        self.text_color = "#2c3e50"
        self.light_text = "#7f8c8d"

        # Store latest module summaries for the Security Dashboard
        self.latest_password_strength_summary = "No password analysis yet."
        self.latest_password_generator_summary = "No password generation yet."
        self.latest_input_validation_summary = "No input validation yet."
        self.latest_port_scanner_summary = "No port scan yet."
        self.latest_traffic_analyzer_summary = "No traffic analysis yet."

        self.root.configure(bg=self.bg_color)
        
        # Configure custom styles for ttk widgets
        self.setup_styles()
        
        # Create main interface
        self.create_main_interface()

        
    
    def setup_styles(self):
        """Configure custom styles for ttk widgets to match color scheme."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook (tab container) style
        style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', padding=[20, 12], font=('Arial', 10, 'bold'))
        
        # Custom tab styles for each module
        style.map('TNotebook.Tab',
                  background=[('selected', self.card_bg)],
                  foreground=[('selected', self.text_color)])
        
        # Configure frame style
        style.configure('TFrame', background=self.bg_color)
        style.configure('Card.TFrame', background=self.card_bg, relief='raised')
    
    def create_main_interface(self):
        """Build the main interface with header and tabbed modules."""
        # Main container
        main_container = tk.Frame(self.root, bg=self.bg_color)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Modern header section
        header_frame = tk.Frame(main_container, bg=self.header_bg)
        header_frame.pack(fill=tk.X)
        
        # Top accent bar
        accent_bar = tk.Frame(header_frame, bg=self.header_accent, height=4)
        accent_bar.pack(fill=tk.X)
        
        # Header content container
        header_content = tk.Frame(header_frame, bg=self.header_bg)
        header_content.pack(fill=tk.X, padx=50, pady=20)
        
        # Main title
        title_label = tk.Label(
            header_content,
            text="🛡️ Security Suite     🛡️",
            font=("Arial", 22, "bold"),
            bg=self.header_bg,
            fg="white"
        )
        title_label.pack(pady=(0, 10))
        
        # Module indicators
        modules_frame = tk.Frame(header_content, bg=self.header_bg)
        modules_frame.pack()
        
        self._create_module_indicator(modules_frame, "", self.teal_color, "A security tool for password checks, safe inputs, and network scanning.")

        
        # Content container
        content_container = tk.Frame(main_container, bg=self.bg_color)
        content_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Main content area for switching between Dashboard, Application Security, and Network Security
        self.main_content = tk.Frame(content_container, bg=self.bg_color)
        self.main_content.pack(fill=tk.BOTH, expand=True)

        # Create the three main views
        self.create_security_dashboard_tab()
        self.create_application_security_tab()
        self.create_network_security_tab()

        # Show Dashboard first
        self.show_dashboard()

        # Add status bar
        self.create_status_bar()

    def _create_module_indicator(self, parent, symbol, color, text):
        """Helper to create colored module indicators in header."""
        indicator_frame = tk.Frame(parent, bg=self.header_bg)
        indicator_frame.pack(side=tk.LEFT, padx=15)
        
        symbol_label = tk.Label(
            indicator_frame,
            text=symbol,
            bg=self.header_bg,
            fg=color,
            font=("Arial", 12, "bold")
        )
        symbol_label.pack(side=tk.LEFT)
        
        text_label = tk.Label(
            indicator_frame,
            text=text,
            bg=self.header_bg,
            fg="#ecf0f1",
            font=("Arial", 10)
        )
        text_label.pack(side=tk.LEFT, padx=(5, 0))

# ==================== TAB SWITCHING FUNCTIONS ====================
    def show_dashboard(self):
        """Show only the Dashboard view."""
        self.application_security_frame.pack_forget()
        self.network_security_frame.pack_forget()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
        self.update_security_dashboard()


    def show_application_security(self):
        """Show only the Application Security view."""
        self.dashboard_frame.pack_forget()
        self.network_security_frame.pack_forget()
        self.application_security_frame.pack(fill=tk.BOTH, expand=True)


    def show_network_security(self):
        """Show only the Network Security view."""
        self.dashboard_frame.pack_forget()
        self.application_security_frame.pack_forget()
        self.network_security_frame.pack(fill=tk.BOTH, expand=True)

# ==================== TAB 1: APPLICATION SECURITY ====================
    def create_application_security_tab(self):
        """Create the Application Security view with nested module tabs."""
        self.application_security_frame = tk.Frame(self.main_content, bg=self.card_bg)

        content = tk.Frame(self.application_security_frame, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header_bar = tk.Frame(content, bg=self.teal_color, height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))

        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 15))

        header_row = tk.Frame(desc_frame, bg=self.card_bg)
        header_row.pack(fill=tk.X)

        tk.Label(
            header_row,
            text="Application Security",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg=self.teal_color
        ).pack(side=tk.LEFT)

        back_btn = tk.Button(
            header_row,
            text="⬅ Back to Dashboard",
            command=self.show_dashboard,
            font=("Arial", 10, "bold"),
            bg="#7f8c8d",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=15,
            pady=8
        )
        back_btn.pack(side=tk.RIGHT)

        tk.Label(
            desc_frame,
            text="This section contains password analysis, password generation, and input security tools.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=900,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))

        self.app_notebook = ttk.Notebook(content)
        self.app_notebook.pack(fill=tk.BOTH, expand=True)

        self.create_password_security_tab(self.app_notebook)
        self.create_input_validator_tab(self.app_notebook)

# ==================== TAB 2: NETWORK SECURITY ====================
    def create_network_security_tab(self):
        """Create the Network Security view with nested module tabs."""

        self.network_security_frame = tk.Frame(self.main_content, bg=self.card_bg)

        content = tk.Frame(self.network_security_frame, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header_bar = tk.Frame(content, bg=self.red_color, height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))

        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 15))

        header_row = tk.Frame(desc_frame, bg=self.card_bg)
        header_row.pack(fill=tk.X)

        tk.Label(
            header_row,
            text="Network Security",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg=self.red_color
        ).pack(side=tk.LEFT)

        back_btn = tk.Button(
            header_row,
            text="⬅ Back to Dashboard",
            command=self.show_dashboard,
            font=("Arial", 10, "bold"),
            bg="#7f8c8d",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=15,
            pady=8
        )
        back_btn.pack(side=tk.RIGHT)

        tk.Label(
            desc_frame,
            text="This section contains network port scanning and network traffic analysis tools.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=900,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))

        self.network_notebook = ttk.Notebook(content)
        self.network_notebook.pack(fill=tk.BOTH, expand=True)

        self.create_port_scanner_tab(self.network_notebook)
        self.create_traffic_analyzer_tab(self.network_notebook)
# ==================== TAB 0: SECURITY DASHBOARD ====================
    def create_security_dashboard_tab(self):
        """Create the Security Dashboard view."""
        self.dashboard_frame = tk.Frame(self.main_content, bg=self.card_bg)

        content = tk.Frame(self.dashboard_frame, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        # Header bar
        header_bar = tk.Frame(content, bg="#2c3e50", height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))

        # Title
        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 20))

        tk.Label(
            desc_frame,
            text="Dashboard",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg="#2c3e50"
        ).pack(anchor="w")

        tk.Label(
            desc_frame,
            text="This dashboard provides the latest summary from all security modules in one place.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=900,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))

        # Navigation buttons to open specific module tabs
        nav_frame = tk.Frame(content, bg=self.card_bg)
        nav_frame.pack(fill=tk.X, pady=(0, 15))

        app_btn = tk.Button(
            nav_frame,
            text="🛡️ Open Application Security",
            command=self.show_application_security,
            font=("Arial", 11, "bold"),
            bg=self.teal_color,
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        )
        app_btn.pack(side=tk.LEFT, padx=5)

        network_btn = tk.Button(
            nav_frame,
            text="🌐 Open Network Security",
            command=self.show_network_security,
            font=("Arial", 11, "bold"),
            bg=self.red_color,
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        )
        network_btn.pack(side=tk.LEFT, padx=5)
        
       # Refresh button
        refresh_btn = tk.Button(
            nav_frame,
            text="🔄 Refresh Dashboard",
            command=self.update_security_dashboard,
            font=("Arial", 11, "bold"),
            bg="#2c3e50",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)

        # Dashboard output area
        dashboard_frame = tk.Frame(content, bg=self.card_bg)
        dashboard_frame.pack(fill=tk.BOTH, expand=True)

        self.dashboard_output = scrolledtext.ScrolledText(
            dashboard_frame,
            font=("Consolas", 10),
            wrap=tk.WORD,
            relief=tk.SOLID,
            borderwidth=1,
            height=20
        )
        self.dashboard_output.pack(fill=tk.BOTH, expand=True)
        self.dashboard_output.config(state=tk.DISABLED)

        # Show initial content
        self.update_security_dashboard()

   

    # ==================== DASHBOARD NAVIGATION FUNCTIONS ====================
    def open_application_security_tab(self):
        """Open the Application Security top-level tab."""
        self.notebook.select(self.tab_application_security)


    def open_network_security_tab(self):
        """Open the Network Security top-level tab."""
        self.notebook.select(self.tab_network_security)

    # ==================== DASHBOARD UPDATE FUNCTION ====================
    def update_security_dashboard(self):
        """Refresh the dashboard with the latest summaries from all modules."""
        dashboard_text = f"{'='*80}\n"
        dashboard_text += "SECURITY DASHBOARD SUMMARY\n"
        dashboard_text += f"{'='*80}\n\n"

        dashboard_text += "[1] PASSWORD CHECK\n"
        dashboard_text += f"{'-'*80}\n"
        dashboard_text += f"{self.latest_password_strength_summary}\n\n"

        dashboard_text += "[2] PASSWORD TOOLS\n"
        dashboard_text += f"{'-'*80}\n"
        dashboard_text += f"{self.latest_password_generator_summary}\n\n"

        dashboard_text += "[3] INPUT SECURITY\n"
        dashboard_text += f"{'-'*80}\n"
        dashboard_text += f"{self.latest_input_validation_summary}\n\n"

        dashboard_text += "[4] PORT SCANNER\n"
        dashboard_text += f"{'-'*80}\n"
        dashboard_text += f"{self.latest_port_scanner_summary}\n\n"

        dashboard_text += "[5] TRAFFIC ANALYZER\n"
        dashboard_text += f"{'-'*80}\n"
        dashboard_text += f"{self.latest_traffic_analyzer_summary}\n\n"

        dashboard_text += f"{'='*80}\n"
        dashboard_text += "Latest module activity is shown above.\n"
        dashboard_text += f"{'='*80}\n"

        self.dashboard_output.config(state=tk.NORMAL)
        self.dashboard_output.delete("1.0", tk.END)
        self.dashboard_output.insert("1.0", dashboard_text)
        self.dashboard_output.config(state=tk.DISABLED)

 # ================== COMBINED Password Security tab ================== 
    def create_password_security_tab(self, parent_notebook):
        """Create the combined Password Security tab."""
        tab = ttk.Frame(parent_notebook)
        self.tab_password_security = tab
        parent_notebook.add(tab, text="🔐 Password Security")

        content = tk.Frame(tab, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        header_bar = tk.Frame(content, bg=self.teal_color, height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))

        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(
            desc_frame,
            text="Password Security",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg=self.teal_color
        ).pack(anchor="w")

        tk.Label(
            desc_frame,
            text="This module combines password entry, password generation, strength analysis, hashing, and password copying in one workspace.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=900,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))

        # Shared password textbox
        shared_pwd_frame = tk.Frame(content, bg=self.card_bg)
        shared_pwd_frame.pack(fill=tk.X, pady=(0, 15))

        tk.Label(
            shared_pwd_frame,
            text="Password:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(anchor="w", pady=(0, 5))

        pwd_entry_row = tk.Frame(shared_pwd_frame, bg=self.card_bg)
        pwd_entry_row.pack(fill=tk.X)

        self.password_security_entry = tk.Entry(
            pwd_entry_row,
            show="•",
            font=("Consolas", 11),
            relief=tk.SOLID,
            borderwidth=1
        )
        self.password_security_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        self.password_security_show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(
            pwd_entry_row,
            text="Show",
            variable=self.password_security_show_var,
            command=self.toggle_password_security_visibility,
            font=("Arial", 10),
            bg=self.card_bg
        ).pack(side=tk.LEFT, padx=(10, 0))

        # Number of Passwords
        config_frame = tk.Frame(content, bg=self.card_bg)
        config_frame.pack(fill=tk.X, pady=(0, 10))

        num_pwd_frame = tk.Frame(config_frame, bg=self.card_bg)
        num_pwd_frame.pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(
            num_pwd_frame,
            text="Number of Passwords:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.num_passwords_var = tk.StringVar(value="1")
        self.num_passwords_spinbox = tk.Spinbox(
            num_pwd_frame,
            from_=1,
            to=100,
            textvariable=self.num_passwords_var,
            font=("Arial", 10),
            width=5,
            relief=tk.SOLID,
            borderwidth=1
        )
        self.num_passwords_spinbox.pack(side=tk.LEFT)
        
        length_frame = tk.Frame(config_frame, bg=self.card_bg)
        length_frame.pack(side=tk.LEFT, padx=(0, 20))

        tk.Label(
            length_frame,
            text="Password Length:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.pwd_length_var = tk.StringVar(value="16")
        length_values = [str(i) for i in range(12, 33)]
        length_dropdown = ttk.Combobox(
            length_frame,
            textvariable=self.pwd_length_var,
            values=length_values,
            state="readonly",
            width=5
        )
        length_dropdown.pack(side=tk.LEFT)

        hash_frame = tk.Frame(config_frame, bg=self.card_bg)
        hash_frame.pack(side=tk.LEFT)

        tk.Label(
            hash_frame,
            text="Hash Algorithm:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.hash_algo_var = tk.StringVar(value="sha256")
        hash_combo = ttk.Combobox(
            hash_frame,
            textvariable=self.hash_algo_var,
            values=["sha256", "sha512", "md5"],
            state="readonly",
            width=10
        )
        hash_combo.pack(side=tk.LEFT)

        tk.Label(
            content,
            text="Note: Can generate up to 100 passwords.",
            font=("Arial", 8, "italic"),
            bg=self.card_bg,
            fg=self.light_text
        ).pack(anchor="w", pady=(0, 10))

        tk.Label(
            content,
            text="Note: Minimum 12 characters required for security | Use 16+ for best security",
            font=("Arial", 8),
            bg=self.card_bg,
            fg=self.light_text
        ).pack(pady=(0, 10))

        button_frame = tk.Frame(content, bg=self.card_bg)
        button_frame.pack(pady=(0, 15))

        tk.Button(
            button_frame,
            text="🔍 Analyze Password",
            command=self.analyze_password_security_entry,
            font=("Arial", 11, "bold"),
            bg=self.teal_color,
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="🔐 Generate Password",
            command=self.generate_passwords_into_shared_entry,
            font=("Arial", 11, "bold"),
            bg=self.purple_color,
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="📋 Copy Password",
            command=self.copy_selected_generated_password,
            font=("Arial", 11, "bold"),
            bg="#3498db",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="💾 Save to File",
            command=self.save_password_security_results,
            font=("Arial", 11, "bold"),
            bg="#3498db",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            button_frame,
            text="🗑️ Clear Results",
            command=self.clear_password_security_results,
            font=("Arial", 11, "bold"),
            bg="#95a5a6",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12
        ).pack(side=tk.LEFT, padx=5)

        select_frame = tk.Frame(content, bg=self.card_bg)
        select_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(
            select_frame,
            text="Select Generated Password:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.selected_generated_password_var = tk.StringVar(value="Password 1")

        self.selected_generated_password_dropdown = ttk.Combobox(
            select_frame,
            textvariable=self.selected_generated_password_var,
            values=[],
            state="readonly",
            width=25
        )
        self.selected_generated_password_dropdown.pack(side=tk.LEFT)

        self.selected_generated_password_dropdown.bind("<<ComboboxSelected>>", self.on_generated_password_selected)

        results_frame = tk.Frame(content, bg=self.card_bg)
        results_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            results_frame,
            text="Password Security Results:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(anchor="w", pady=(0, 5))

        self.password_security_output = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 10),
            wrap=tk.WORD,
            relief=tk.SOLID,
            borderwidth=1,
            height=15
        )
        self.password_security_output.pack(fill=tk.BOTH, expand=True)
        self.password_security_output.config(state=tk.DISABLED)
# ==================== HELPER METHODS  ====================
    def toggle_password_security_visibility(self):
        """Toggle password visibility in the combined Password Security tab."""
        if self.password_security_show_var.get():
            self.password_security_entry.config(show="")
        else:
            self.password_security_entry.config(show="•")
    
    def analyze_password_security_entry(self):
        """Analyze the currently selected or typed password using the polished strength-analysis format."""
        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Analyzing password")

        password = ""

        # If generated passwords exist, analyze the currently selected dropdown password
        if hasattr(self, 'generated_passwords_list') and self.generated_passwords_list:
            selected_label = self.selected_generated_password_var.get()

            if selected_label:
                try:
                    selected_index = int(selected_label.split()[-1]) - 1
                    password = self.generated_passwords_list[selected_index]["password"]

                    # Keep the textbox synchronized with the selected generated password
                    self.password_security_entry.delete(0, tk.END)
                    self.password_security_entry.insert(0, password)

                except (ValueError, IndexError):
                    password = self.password_security_entry.get().strip()
            else:
                password = self.password_security_entry.get().strip()
        else:
            password = self.password_security_entry.get().strip()

        if not password:
            messagebox.showwarning("Empty Input", "Please enter or generate a password first.")
            return

        score, rating, feedback_notes, checks = PasswordStrengthAssessment().evaluate_password_strength(password)

        result_text = f"{'='*60}\n"
        result_text += "PASSWORD STRENGTH ANALYSIS\n"
        result_text += f"{'='*60}\n\n"
        result_text += f"Overall Rating: {rating}\n"
        result_text += f"Security Score: {score}/7\n\n"

        result_text += f"{'─'*60}\n"
        result_text += "Detailed Security Checks:\n"
        result_text += f"{'─'*60}\n"

        self.password_security_output.config(state=tk.NORMAL)
        self.password_security_output.delete("1.0", tk.END)
        self.password_security_output.insert("1.0", result_text)

        self.password_security_output.tag_configure("pass", foreground="#27ae60")
        self.password_security_output.tag_configure("fail", foreground="#e74c3c")

        checks_list = [
            ("✓ Length (≥12 chars):     ", checks['length']),
            ("✓ Uppercase Letters:      ", checks['has_upper']),
            ("✓ Lowercase Letters:      ", checks['has_lower']),
            ("✓ Numeric Digits:         ", checks['has_digit']),
            ("✓ Special Characters:     ", checks['has_special'])
        ]

        for label, passed in checks_list:
            self.password_security_output.insert(tk.END, label)
            if passed:
                self.password_security_output.insert(tk.END, "PASS\n", "pass")
            else:
                self.password_security_output.insert(tk.END, "FAIL\n", "fail")

        self.password_security_output.insert(tk.END, "\n")

        if feedback_notes:
            self.password_security_output.insert(tk.END, f"{'─'*60}\n")
            self.password_security_output.insert(tk.END, "Recommendations for Improvement:\n")
            self.password_security_output.insert(tk.END, f"{'─'*60}\n")
            for note in feedback_notes:
                self.password_security_output.insert(tk.END, f"{note}\n")
        else:
            self.password_security_output.insert(tk.END, f"{'─'*60}\n")
            self.password_security_output.insert(tk.END, "✓ Excellent! This password meets all security criteria.\n")
            self.password_security_output.insert(tk.END, f"{'─'*60}\n")

        self.password_security_output.config(state=tk.DISABLED)

        summary_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.latest_password_strength_summary = (
            f"Time: {summary_time}\n"
            f"Rating: {rating}\n"
            f"Score: {score}/7"
        )
        self.update_security_dashboard()
        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Password analysis complete")

    def generate_passwords_into_shared_entry(self):
        """Generate password(s), fill the shared password box, and list them in the results area."""
        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Generating password")

        raw_num_passwords = self.num_passwords_spinbox.get().strip()

        if not raw_num_passwords:
            messagebox.showerror("Input Error", "Number of passwords is required.")
            return

        if not raw_num_passwords.isdigit():
            messagebox.showerror("Input Error", "Number of passwords must be a valid whole number.")
            return

        num_passwords = int(raw_num_passwords)

        if num_passwords < 1:
            messagebox.showerror("Input Error", "Number of passwords must be at least 1.")
            return

        if num_passwords > 100:
            messagebox.showerror("Input Error", "Number of passwords must not exceed 100.")
            return

        if num_passwords < 1:
            messagebox.showerror("Input Error", "Number of passwords must be at least 1.")
            return

        if num_passwords > 100:
            messagebox.showerror("Input Error", "Number of passwords must not exceed 100.")
            return

        try:
            length = int(self.pwd_length_var.get())
        except ValueError:
            messagebox.showerror("Input Error", "Password length must be a valid number.")
            return

        if length < 12 or length > 32:
            messagebox.showerror("Input Error", "Password length must be between 12 and 32.")
            return

        algorithm = self.hash_algo_var.get()

        self.generated_passwords_list = []
        self.pwd_generator = PasswordGenerator()

        result_text = f"{'='*80}\n"
        result_text += "SECURE PASSWORD GENERATION RESULTS\n"
        result_text += f"{'='*80}\n\n"

        for i in range(num_passwords):
            password = self.pwd_generator.generate_random_password(length)
            password_hash = self.pwd_generator.hash_password(password, algorithm)
            score, rating, feedback_notes, checks = PasswordStrengthAssessment().evaluate_password_strength(password)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            self.generated_passwords_list.append({
                "password": password,
                "hash": password_hash,
                "algorithm": algorithm,
                "strength": rating,
                "score": score,
                "timestamp": timestamp
            })

            result_text += f"Password #{i+1}:\n"
            result_text += f"  Timestamp:         {timestamp}\n"
            result_text += f"  Password:          {password}\n"
            result_text += f"  Length:            {len(password)} characters\n"
            result_text += f"  Strength Rating:   {rating}\n"
            result_text += f"  Security Score:    {score}/7\n"
            result_text += f"  Hash ({algorithm.upper()}):   {password_hash}\n\n"

            result_text += "  Security Checks:\n"
            result_text += f"    ✓ 12+ Characters:  {'YES' if checks['length'] else 'NO'}\n"
            result_text += f"    ✓ Uppercase:       {'YES' if checks['has_upper'] else 'NO'}\n"
            result_text += f"    ✓ Lowercase:       {'YES' if checks['has_lower'] else 'NO'}\n"
            result_text += f"    ✓ Digits:          {'YES' if checks['has_digit'] else 'NO'}\n"
            result_text += f"    ✓ Special Chars:   {'YES' if checks['has_special'] else 'NO'}\n"
            result_text += f"{'-'*80}\n\n"

        self.current_generated_password = self.generated_passwords_list[-1] if self.generated_passwords_list else None

        if self.current_generated_password:
            self.password_security_entry.delete(0, tk.END)
            self.password_security_entry.insert(0, self.current_generated_password["password"])

        password_labels = [f"Password {i+1}" for i in range(len(self.generated_passwords_list))]
        self.selected_generated_password_dropdown["values"] = password_labels
        if password_labels:
            self.selected_generated_password_var.set(password_labels[0])

        result_text += f"{'='*80}\n"
        result_text += f"✓ Generated {num_passwords} password(s) successfully!\n"
        result_text += f"{'='*80}\n"

        self.password_security_output.config(state=tk.NORMAL)
        self.password_security_output.delete("1.0", tk.END)
        self.password_security_output.insert("1.0", result_text)
        self.password_security_output.config(state=tk.DISABLED)

        summary_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.latest_password_generator_summary = (
            f"Time: {summary_time}\n"
            f"Generated: {num_passwords} password(s)\n"
            f"Latest Strength: {self.current_generated_password['strength'] if self.current_generated_password else 'N/A'}\n"
            f"Algorithm: {algorithm.upper()}"
        )
        self.update_security_dashboard()
        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Password generation complete") 

    def copy_selected_generated_password(self):
        """Copy the selected generated password to the clipboard."""
        if not hasattr(self, "generated_passwords_list") or not self.generated_passwords_list:
            messagebox.showwarning("No Password Available", "Please generate at least one password first.")
            return

        selected_label = self.selected_generated_password_var.get()
        if not selected_label:
            messagebox.showwarning("No Selection", "Please select a generated password first.")
            return

        try:
            selected_index = int(selected_label.split()[-1]) - 1
            password = self.generated_passwords_list[selected_index]["password"]
        except (ValueError, IndexError):
            messagebox.showerror("Selection Error", "The selected password could not be found.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        self.root.update()
        messagebox.showinfo("Copied", "The selected password was copied to the clipboard.")

    def on_generated_password_selected(self, event=None):
        """Update the shared password textbox when a generated password is selected."""
        if not hasattr(self, 'generated_passwords_list') or not self.generated_passwords_list:
            return

        selected_label = self.selected_generated_password_var.get()
        if not selected_label:
            return

        try:
            selected_index = int(selected_label.split()[-1]) - 1
            password = self.generated_passwords_list[selected_index]["password"]

            self.password_security_entry.delete(0, tk.END)
            self.password_security_entry.insert(0, password)
        except (ValueError, IndexError):
            pass

    def save_password_security_results(self):
        """Save all generated passwords from the Password Security module to a file."""
        if not hasattr(self, 'generated_passwords_list') or not self.generated_passwords_list:
            messagebox.showwarning("No Passwords", "Please generate password(s) first.")
            return

        file_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        default_filename = f"gen_pwd_{file_timestamp}.txt"

        file_path = filedialog.asksaveasfilename(
            defaultextension="txt",
            filetypes=[("Text File", "*.txt")],
            initialfile=default_filename,
            title="Save Generated Password(s)"
        )

        if not file_path:
            return

        try:
            pwd_generator = PasswordGenerator()

            for pwd_data in self.generated_passwords_list:
                pwd_generator.save_password_to_file(
                    pwd_data['password'],
                    pwd_data['hash'],
                    pwd_data['strength'],
                    filename=file_path
                )

            messagebox.showinfo(
                "Success",
                f"{len(self.generated_passwords_list)} password(s) saved successfully."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password(s): {str(e)}")

    def clear_password_security_results(self):
        """Clear the Password Security input, selection, and results."""
        self.password_security_entry.delete(0, tk.END)

        self.password_security_output.config(state=tk.NORMAL)
        self.password_security_output.delete("1.0", tk.END)
        self.password_security_output.config(state=tk.DISABLED)

        self.generated_passwords_list = []
        self.current_generated_password = None

        self.selected_generated_password_dropdown["values"] = []
        self.selected_generated_password_var.set("Password 1")

        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Password Security cleared")

        # ==================== TAB 3: INPUT VALIDATION ====================    
    def create_input_validator_tab(self, parent_notebook):
        """Create the web form input validation and sanitization interface tab."""
        tab = ttk.Frame(parent_notebook)
        self.tab_input_validator = tab
        parent_notebook.add(tab, text="✓ Input Security")
        
        # Content container
        content = tk.Frame(tab, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Module header with orange accent
        header_bar = tk.Frame(content, bg=self.orange_color, height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))
        
        # Description section
        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            desc_frame,
            text="Web Form Input Validator",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg=self.orange_color
        ).pack(anchor="w")
        
        tk.Label(
            desc_frame,
            text="Validates and sanitizes user input to prevent XSS, SQL injection, and format violations. "
                 "Essential for maintaining data integrity and security.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=800,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))
        
       # Input form section
        form_frame = tk.Frame(content, bg=self.card_bg)
        form_frame.pack(fill=tk.X, pady=(0, 15))

        # First Name and Last Name row
        tk.Label(
            form_frame,
            text="First Name:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).grid(row=0, column=0, sticky="w", pady=(0, 10), padx=(0, 10))

        self.first_name_entry = tk.Entry(
            form_frame,
            font=("Arial", 10),
            relief=tk.SOLID,
            borderwidth=1
        )
        self.first_name_entry.grid(row=0, column=1, sticky="ew", pady=(0, 10), ipady=5, padx=(0, 20))

        tk.Label(
            form_frame,
            text="Last Name:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).grid(row=0, column=2, sticky="w", pady=(0, 10), padx=(0, 10))

        self.last_name_entry = tk.Entry(
            form_frame,
            font=("Arial", 10),
            relief=tk.SOLID,
            borderwidth=1
        )
        self.last_name_entry.grid(row=0, column=3, sticky="ew", pady=(0, 10), ipady=5)

        # Email field
        tk.Label(
            form_frame,
            text="Email Address:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).grid(row=1, column=0, sticky="w", pady=(0, 10), padx=(0, 10))

        self.email_entry = tk.Entry(
            form_frame,
            font=("Arial", 10),
            relief=tk.SOLID,
            borderwidth=1
        )
        self.email_entry.grid(row=1, column=1, columnspan=3, sticky="ew", pady=(0, 10), ipady=5)

        # Username field
        tk.Label(
            form_frame,
            text="Username:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).grid(row=2, column=0, sticky="w", pady=(0, 10), padx=(0, 10))

        self.username_entry = tk.Entry(
            form_frame,
            font=("Arial", 10),
            relief=tk.SOLID,
            borderwidth=1
        )
        self.username_entry.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(0, 10), ipady=5)

        # Message field
        tk.Label(
            form_frame,
            text="Message / Comment:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).grid(row=3, column=0, sticky="nw", pady=(0, 10), padx=(0, 10))

        self.message_text = tk.Text(
            form_frame,
            font=("Arial", 10),
            relief=tk.SOLID,
            borderwidth=1,
            height=5,
            wrap=tk.WORD
        )
        self.message_text.grid(row=3, column=1, columnspan=3, sticky="ew", pady=(0, 10))

        # Configure grid weights for responsive layout
        form_frame.columnconfigure(1, weight=1)
        form_frame.columnconfigure(3, weight=1)
                
        button_frame = tk.Frame(content, bg=self.card_bg)
        button_frame.pack(pady=(0, 20))

        validate_btn = tk.Button(
            button_frame,
            text="✓ Validate & Sanitize Input",
            command=self.validate_inputs,
            font=("Arial", 11, "bold"),
            bg=self.orange_color,
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12,
            activebackground="#d35400"
        )
        validate_btn.pack(side=tk.LEFT, padx=5)

        clear_btn = tk.Button(
            button_frame,
            text="🗑️ Clear Results",
            command=self.clear_input_security_results,
            font=("Arial", 11, "bold"),
            bg="#95a5a6",
            fg="white",
            cursor="hand2",
            relief=tk.FLAT,
            padx=20,
            pady=12,
            activebackground="#7f8c8d"
        )
        clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Results section with expandable output
        results_frame = tk.Frame(content, bg=self.card_bg)
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(
            results_frame,
            text="Validation & Sanitization Results:",
            font=("Arial", 10, "bold"),
            bg=self.card_bg,
            fg=self.text_color
        ).pack(anchor="w", pady=(0, 5))
        
        # Scrolled text widget for expandable results
        self.validator_output = scrolledtext.ScrolledText(
            results_frame,
            font=("Consolas", 10),
            wrap=tk.WORD,
            relief=tk.SOLID,
            borderwidth=1,
            height=12
        )
        self.validator_output.pack(fill=tk.BOTH, expand=True)
        self.validator_output.config(state=tk.DISABLED)
    
    def validate_inputs(self):
        """Execute validation and sanitization on all form inputs."""
        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Validating input")
        # Collect form data
        form_data = {
            "First Name": self.first_name_entry.get(),
            "Last Name": self.last_name_entry.get(),
            "Email Address": self.email_entry.get(),
            "Username": self.username_entry.get(),
            "Message / Comment": self.message_text.get("1.0", tk.END).strip()
        }
        
        # Check for empty required fields
        missing_fields = [field for field in form_data if not form_data[field].strip()]
        if missing_fields:
            messagebox.showerror(
                "Missing Required Fields",
                f"The following fields are required:\n" + "\n".join(f"• {field}" for field in missing_fields)
            )
            return
        
        # Validate and sanitize each field
        validation_results = {}
        sanitized_data = {}
        sanitization_notes = {}

        input_validator = InputValidation()
        
        for field_name, value in form_data.items():
            is_valid, errors = input_validator.validate_field(field_name, value)
            sanitized, note = input_validator.sanitize_field(field_name, value)
            
            sanitized_data[field_name] = sanitized
            
            # Determine validation status
            if is_valid and note:
                validation_results[field_name] = ("Sanitized", note)
            elif is_valid:
                validation_results[field_name] = ("Valid", None)
            else:
                validation_results[field_name] = ("Invalid", errors)
        
        # Display results with colored text
        self.validator_output.config(state=tk.NORMAL)
        self.validator_output.delete("1.0", tk.END)
        
        # Configure color tags
        self.validator_output.tag_configure("valid", foreground="#27ae60")  # Green
        self.validator_output.tag_configure("invalid", foreground="#e74c3c")  # Red
        self.validator_output.tag_configure("sanitized", foreground="#f39c12")  # Orange/Warning
        
        self.validator_output.insert(tk.END, f"{'='*70}\n")
        self.validator_output.insert(tk.END, f"INPUT VALIDATION & SANITIZATION REPORT\n")
        self.validator_output.insert(tk.END, f"{'='*70}\n\n")
        
        self.validator_output.insert(tk.END, f"Validation Results:\n")
        self.validator_output.insert(tk.END, f"{'-'*70}\n")
        
        for field_name in form_data.keys():
            status, details = validation_results[field_name]
            
            if status == "Valid":
                self.validator_output.insert(tk.END, f"  - {field_name}: ")
                self.validator_output.insert(tk.END, "Valid\n", "valid")
            elif status == "Sanitized":
                self.validator_output.insert(tk.END, f"  - {field_name}: ")
                self.validator_output.insert(tk.END, f"Sanitized ({details})\n", "sanitized")
            else:
                self.validator_output.insert(tk.END, f"  - {field_name}: ")
                self.validator_output.insert(tk.END, "Invalid\n", "invalid")
                for error in details:
                    self.validator_output.insert(tk.END, f"      {error}\n")
        
        self.validator_output.insert(tk.END, f"\n{'-'*70}\n")
        self.validator_output.insert(tk.END, f"Sanitized Output:\n")
        self.validator_output.insert(tk.END, f"{'-'*70}\n")
        
        for field_name, sanitized_value in sanitized_data.items():
            self.validator_output.insert(tk.END, f"{field_name}: {sanitized_value}\n")
        
        self.validator_output.insert(tk.END, f"\n{'-'*70}\n")
        self.validator_output.insert(tk.END, f"Process Complete.\n")
        self.validator_output.insert(tk.END, f"{'='*70}\n")
        
        self.validator_output.config(state=tk.DISABLED)
        self.status_label.config(text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Input validation complete")
        
        # Update latest summary for dashboard
        valid_count = sum(1 for status, _ in validation_results.values() if status == "Valid")
        sanitized_count = sum(1 for status, _ in validation_results.values() if status == "Sanitized")
        invalid_count = sum(1 for status, _ in validation_results.values() if status == "Invalid")

        summary_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.latest_input_validation_summary = (
            f"Time: {summary_time}\n"
            f"Validation completed\n"
            f"Valid fields: {valid_count}\n"
            f"Sanitized fields: {sanitized_count}\n"
            f"Invalid fields: {invalid_count}"
        )
        self.update_security_dashboard()
    
    def clear_input_security_results(self):
        """Clear only the Input Security results box."""
        self.validator_output.config(state=tk.NORMAL)
        self.validator_output.delete("1.0", tk.END)
        self.validator_output.config(state=tk.DISABLED)

        self.status_label.config(
            text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Input Security results cleared"
        )
            

    # ==================== TAB 4: PORT SCANNER ====================
    def create_port_scanner_tab(self, parent_notebook):
        """Create the network port scanning interface tab."""
        tab = ttk.Frame(parent_notebook)
        self.tab_port_scanner = tab
        parent_notebook.add(tab, text="📡 Port Scanner")
        
        # Content container
        content = tk.Frame(tab, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Module header with blue accent
        header_bar = tk.Frame(content, bg="#3498db", height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))
        
        # Description section
        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            desc_frame,
            text="Network Port Scanner",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg=self.blue_color
        ).pack(anchor="w")
        
        tk.Label(
            desc_frame,
            text="Scans specified IP addresses or hostnames for open ports and identifies common services running on those ports.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=800,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))
         
        # Initialize modules in their respective tabs
        self.port_scanner = PortScanner(content) 
        # Set reference to parent GUI for inter-module communication (e.g., from Traffic Analyzer)
        self.port_scanner.parent_gui = self       
                    

    # ==================== TAB 5: TRAFFIC ANALYZER ====================
    def create_traffic_analyzer_tab(self, parent_notebook):
        """Create the network traffic analysis interface tab."""
        tab = ttk.Frame(parent_notebook)
        self.tab_traffic_analyzer = tab
        parent_notebook.add(tab, text="📊 Traffic Analyzer")
        
        # Content container
        content = tk.Frame(tab, bg=self.card_bg)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Module header with dark blue accent
        header_bar = tk.Frame(content, bg=self.red_color, height=3)
        header_bar.pack(fill=tk.X, pady=(0, 15))
        
        # Description section
        desc_frame = tk.Frame(content, bg=self.card_bg)
        desc_frame.pack(fill=tk.X, pady=(0, 20))
        
        tk.Label(
            desc_frame,
            text="Network Traffic Analyzer",
            font=("Segoe UI", 14, "bold"),
            bg=self.card_bg,
            fg=self.red_color
        ).pack(anchor="w")
        
        tk.Label(
            desc_frame,
            text="Monitors and analyzes network traffic in real-time to identify potential security threats and unusual patterns.",
            font=("Arial", 10),
            bg=self.card_bg,
            fg=self.text_color,
            wraplength=800,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))

        # Initialize modules in their respective tabs
        self.traffic_analyzer = NetworkAnalyzer(content)
        self.traffic_analyzer.parent_gui = self
        self.traffic_analyzer.on_ip_click = self.open_port_scanner_with_ip # Set callback for IP clicks in traffic analyzer

    def refresh_top_ips(self):
        """Display Top 5 destination IPs as underlined clickable links."""
        if not hasattr(self, "traffic_analyzer") or not self.traffic_analyzer.destination_ips:
            messagebox.showinfo("No Data", "No traffic data yet. Run Start Capture first.")
            return

        # Top 5 destination IPs
        top_ips = sorted(
            self.traffic_analyzer.destination_ips.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        self.top_ips_text.config(state="normal")
        self.top_ips_text.delete("1.0", tk.END)

        # Map tag → IP for click handling
        self.top_ip_map = {}

        for i, (ip, count) in enumerate(top_ips, start=1):
            domain = self.traffic_analyzer.resolve_ip_to_domain(ip)
            if domain == ip:
                domain = "No domain"

            tag = f"ip_link_{i}"
            self.top_ip_map[tag] = ip

            # Print list line
            self.top_ips_text.insert(tk.END, f"{i}) ")

            # Insert IP with clickable tag
            self.top_ips_text.insert(tk.END, ip, tag)
            self.top_ips_text.insert(tk.END, f"  —  {domain}  —  {count} pkts\n")

            # Style the tag like a hyperlink
            self.top_ips_text.tag_config(tag, underline=True)

            # Click event: open scanner
            self.top_ips_text.tag_bind(tag, "<Button-1>", self.on_ip_link_click)

        self.top_ips_text.config(state="disabled")

    def on_ip_link_click(self, event):
        """When an IP link is clicked, switch to Port Scanner and autofill target + preset."""
        # Identify which tag was clicked
        tags = self.top_ips_text.tag_names(tk.CURRENT)

        clicked_ip = None
        for t in tags:
            if hasattr(self, "top_ip_map") and t in self.top_ip_map:
                clicked_ip = self.top_ip_map[t]
                break

        if not clicked_ip:
            return

        self.open_port_scanner_with_ip(clicked_ip)

    def open_port_scanner_with_ip(self, ip):
        """Switch to Port Scanner tab, autofill IP, reset scanner state, and prepare for scanning."""
        # Clear previous scan output and reset scanner state
        self.port_scanner.clear_results()
        self.port_scanner.filter_var.set("all")

        # Reset progress display
        self.port_scanner.progress_var.set(0)
        self.port_scanner.progress_status.config(text="Ready to scan selected IP from Traffic Analyzer")

        # Fill IP field
        self.port_scanner.ip_entry.delete(0, tk.END)
        self.port_scanner.ip_entry.insert(0, ip)

        # Set default preset to Top 20 ports
        self.port_scanner.preset_var.set("Common Ports (Top 20)")
        self.port_scanner.apply_preset()

        # Switch tab
        self.show_network_security()
        self.network_notebook.select(self.tab_port_scanner)

        # Show a short message in the scanner output area
        self.port_scanner.output_text.config(state=tk.NORMAL)
        self.port_scanner.output_text.insert(
            tk.END,
            f"Selected IP from Traffic Analyzer: {ip}\nReady to scan using preset: Common Ports (Top 20)\n",
            "info"
        )
        self.port_scanner.output_text.config(state=tk.DISABLED) 

    def create_status_bar(self):
        """Create application status bar"""
        status_frame = tk.Frame(self.root, bg="#ecf0f1", height=30, relief=tk.SUNKEN, bd=1)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready  |  Terminal Assessment Security Tool v3.0  |  Status: Idle",
            font=("Arial", 10),
            bg="#ecf0f1",
            fg="#2c3e50",
            anchor=tk.W,
            padx=10
        )
        self.status_label.pack(fill=tk.X)

# ==================== APPLICATION ENTRY POINT ====================
def main():
    root = tk.Tk()
    app = SecuritySuiteGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
