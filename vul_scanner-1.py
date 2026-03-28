import tkinter as tk
import customtkinter as ctk
import threading
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Theme Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class ProfessionalScanner(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("SENTINEL | Advanced Web Vulnerability Scanner")
        self.geometry("1000x650")

        # --- Original Payloads (Unchanged) ---
        self.SQLI_PAYLOADS = ["' OR '1'='1", "' OR 1=1--", "'--"]
        self.XSS_PAYLOAD = "<script>alert('XSS')</script>"
        self.LFI_PAYLOAD = "../../../../etc/passwd"

        # Grid Layout (Sidebar + Main)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="SENTINEL", font=ctk.CTkFont(size=24, weight="bold", family="Orbitron"))
        self.logo.grid(row=0, column=0, padx=20, pady=(30, 10))
        
        self.version = ctk.CTkLabel(self.sidebar, text="v2.0.4 - Core Engine", text_color="#555555")
        self.version.grid(row=1, column=0, padx=20, pady=(0, 30))

        # Stats indicators
        self.stat_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stat_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        self.vuln_found_label = ctk.CTkLabel(self.stat_frame, text="Vulnerabilities: 0", text_color="#e74c3c", font=ctk.CTkFont(weight="bold"))
        self.vuln_found_label.pack(anchor="w")
        
        self.forms_scanned_label = ctk.CTkLabel(self.stat_frame, text="Forms Scanned: 0", text_color="#3498db")
        self.forms_scanned_label.pack(anchor="w", pady=5)

        # --- MAIN PANEL ---
        self.main_container = ctk.CTkFrame(self, corner_radius=15, fg_color="#1a1a1a")
        self.main_container.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")
        self.main_container.grid_columnconfigure(0, weight=1)

        # Header/Input
        self.header_label = ctk.CTkLabel(self.main_container, text="Target Security Audit", font=ctk.CTkFont(size=18))
        self.header_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")

        self.url_input = ctk.CTkEntry(self.main_container, placeholder_text="https://target-site.com", height=45, font=("Consolas", 14))
        self.url_input.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.scan_btn = ctk.CTkButton(self.main_container, text="LAUNCH ATTACK SURFACE SCAN", font=ctk.CTkFont(weight="bold"), 
                                      height=45, fg_color="#1f538d", hover_color="#2980b9", command=self.start_thread)
        self.scan_btn.grid(row=2, column=0, padx=20, pady=10, sticky="ew")

        # Console Output
        self.console = ctk.CTkTextbox(self.main_container, font=("Consolas", 13), fg_color="#000000", text_color="#00ff00")
        self.console.grid(row=3, column=0, padx=20, pady=20, sticky="nsew")
        self.main_container.grid_rowconfigure(3, weight=1)

        # Footer Progress
        self.progress = ctk.CTkProgressBar(self.main_container, height=10, progress_color="#1f538d")
        self.progress.grid(row=4, column=0, padx=20, pady=(0, 20), sticky="ew")
        self.progress.set(0)

        # Tracking variables
        self.vuln_count = 0

    # --- Scanner Logic (Your Code, Integrated) ---

    def log(self, text, color="white"):
        self.console.insert("end", f" {text}\n")
        self.console.see("end")

    def run_security_audit(self):
        url = self.url_input.get().strip()
        if not url:
            self.log("[!] ERROR: Target URL required.")
            return

        # Reset UI
        self.scan_btn.configure(state="disabled", text="SCANNING...")
        self.console.delete("0.0", "end")
        self.vuln_count = 0
        self.vuln_found_label.configure(text="Vulnerabilities: 0")
        
        self.log(f"[*] Initializing Sentinel Engine on: {url}")
        self.progress.set(0.1)

        try:
            res = requests.get(url, timeout=5)
            soup = BeautifulSoup(res.text, "html.parser")
            forms = soup.find_all("form")
            self.forms_scanned_label.configure(text=f"Forms Scanned: {len(forms)}")
            
            if not forms:
                self.log("[-] No entry points (forms) detected on this page.")
            
            for i, form in enumerate(forms):
                self.log(f"\n[+] Analyzing Entry Point #{i+1}...")
                details = self.extract_form_details(form)
                target_url = urljoin(url, details["action"])

                # Test SQLi
                self.log(f"  > Testing SQL Injection...")
                for payload in self.SQLI_PAYLOADS:
                    res = self.submit(details, url, payload)
                    if res and ("sql" in res.text.lower() or "error" in res.text.lower()):
                        self.log("  [!] CRITICAL: SQL Injection vulnerability found!", "#e74c3c")
                        self.update_vuln_count()
                        break

                # Test XSS
                self.log(f"  > Testing Cross-Site Scripting...")
                res = self.submit(details, url, self.XSS_PAYLOAD)
                if res and self.XSS_PAYLOAD in res.text:
                    self.log("  [!] HIGH: XSS vulnerability detected!")
                    self.update_vuln_count()

                # Test LFI
                self.log(f"  > Testing Local File Inclusion...")
                res = self.submit(details, url, self.LFI_PAYLOAD)
                if res and "root:x:" in res.text:
                    self.log("  [!] HIGH: LFI vulnerability detected!")
                    self.update_vuln_count()

                # Test CSRF
                self.log(f"  > Checking CSRF protection...")
                if not form.find("input", {"type": "hidden"}):
                    self.log("  [!] MEDIUM: No CSRF tokens found.")
                    self.update_vuln_count()

                self.progress.set((i + 1) / len(forms))

        except Exception as e:
            self.log(f"[!] SYSTEM ERROR: {str(e)}")

        self.log("\n--- AUDIT COMPLETE ---")
        self.scan_btn.configure(state="normal", text="LAUNCH ATTACK SURFACE SCAN")
        self.progress.set(1.0)

    def extract_form_details(self, form):
        return {
            "action": form.attrs.get("action", ""),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": [i.attrs.get("name") for i in form.find_all("input") if i.attrs.get("name")]
        }

    def submit(self, details, url, payload):
        target = urljoin(url, details["action"])
        data = {name: payload for name in details["inputs"] if name}
        try:
            if details["method"] == "post":
                return requests.post(target, data=data, timeout=5)
            return requests.get(target, params=data, timeout=5)
        except: return None

    def update_vuln_count(self):
        self.vuln_count += 1
        self.vuln_found_label.configure(text=f"Vulnerabilities: {self.vuln_count}")

    def start_thread(self):
        # This keeps the GUI responsive while scanning
        thread = threading.Thread(target=self.run_security_audit)
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    app = ProfessionalScanner()
    app.mainloop()