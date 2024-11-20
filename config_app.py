import re
import os
import tkinter as tk
from tkinter import ttk, messagebox, font
import threading
import time
import queue
import atexit
import logging
import sys

# Custom Imports
from .gui_utils import enforce_single_instance, on_exit
from .appdata import UserDataDirectory, find_default_user_data_dir
from ._configure import konfigurasie

# Define the application name
app_name = "azgraphx-auth"
lockfile_name = f"{app_name}.lock"

# Construct the path to the lockfile
base_dir = find_default_user_data_dir()
lockfile_path = os.path.join(base_dir, lockfile_name)
lock = enforce_single_instance(lockfile_path)
if lock is None:
    print("Another instance is already running.")
    sys.exit(1)

# Register cleanup handler on exit
atexit.register(on_exit, lock, lockfile_path)

# Configure dirs
app_dir = UserDataDirectory(dirname=konfigurasie.cred_dirname.get(), auto_remove=False)
app_dir.Clean(alldirs=True)
app_placementdir = app_dir.Dir()


def validate_client_id(client_id):
    uuid_regex = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
    if not uuid_regex.match(client_id):
        messagebox.showerror("Error", "Client ID is not a valid UUID.")
        return False    
    return True

def validate_tenant_id(tenant_id):
    uuid_regex = re.compile(r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$")
    if not uuid_regex.match(tenant_id):
        messagebox.showerror("Error", "Tenant ID is not a valid UUID.")
        return False
    return True

def validate_client_secret(client_secret):
    if len(client_secret) < 20:
        messagebox.showerror("Error", "Client Secret is too short. It must be at least 20 characters.")
        return False
    if not re.search(r"[A-Z]", client_secret):
        messagebox.showerror("Error", "Client Secret must contain at least one uppercase letter.")
        return False
    if not re.search(r"[a-z]", client_secret):
        messagebox.showerror("Error", "Client Secret must contain at least one lowercase letter.")
        return False
    if not re.search(r"\d", client_secret):
        messagebox.showerror("Error", "Client Secret must contain at least one number.")
        return False
    return True
   
def clean_credential_input(input_value):
    return input_value.strip().replace('"', '').replace("'", '')

def create_env_file_with_comments(variables, filename=app_placementdir, comments=None):
    if os.path.isdir(filename):
        filename = os.path.join(filename, '.env')
    with open(filename, 'w') as f:
        for key, value in variables.items():
            if value:
                if comments and key in comments:
                    f.write(f"# {comments[key]}\n")
                f.write(f"{key}={value}\n")
            
            


# Build Configuration App
#-----------------------------------------------------------------------------
class CredentialsWindow(tk.Tk):
    WINDOW_WIDTH = 800
    WINDOW_HEIGHT = 600
	
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.running = True
        self.run_thread = True  # Flag to control thread execution        
        self.previous_screen_width = None
        self.previous_screen_height = None        
        self.init_queue()
        self.init_ui()

    def init_ui(self):
        self.title("Configure Microsoft Graph Credentials")
        self.deiconify()
        self.geometry(f'{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}')        
        self.minsize(self.WINDOW_WIDTH, self.WINDOW_HEIGHT)
        self.resizable(False, False)      
        self.create_view()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def init_queue(self):
        self.queue = queue.Queue()
        self.monitor_thread = threading.Thread(target=self.monitor_resolution)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        self.process_queue()

    def monitor_resolution(self):
        while self.running:
            if not self.run_thread:
                return
            screen_width = self.winfo_screenwidth()
            screen_height = self.winfo_screenheight()
            if (screen_width != self.previous_screen_width or screen_height != self.previous_screen_height):
                self.queue.put((screen_width, screen_height))
                self.previous_screen_width = screen_width
                self.previous_screen_height = screen_height
            time.sleep(1)
            
    def process_queue(self):
        if self.running:
            try:
                screen_width, screen_height = self.queue.get_nowait()
                self.set_window_center(screen_width, screen_height)
            except queue.Empty:
                pass
            self.after(100, self.process_queue)

    def set_window_center(self, screen_width, screen_height):
        center_x = int((screen_width - self.WINDOW_WIDTH) / 2)
        center_y = int((screen_height - self.WINDOW_HEIGHT) / 2)
        self.geometry(f"{self.WINDOW_WIDTH}x{self.WINDOW_HEIGHT}+{center_x}+{center_y}")       

    def create_view(self):
        large_font = font.Font(size=10, weight='bold')
        large_font2 = font.Font(size=10)        
        header_font = font.Font(size=12, weight='bold', underline=True)

        self.auth_var = tk.StringVar(value="interactive")       

        # Header for authentication method selection
        #=========================================================================================           
        auth_header = tk.Label(self, text="Select Authentication Method", font=header_font, anchor="w")
        auth_header.grid(row=0, column=0, sticky=tk.W, padx=20, pady=(10, 5))

        auth_methods = {
            "Interactive Authentication": "interactive",
            "Client Credentials Authentication": "client_credentials",
            "Device Code Flow Authentication": "device_code",
            "Silent Authentication": "silent"
        }

        row = 1
        for text, value in auth_methods.items():
            tk.Radiobutton(self, text=text, variable=self.auth_var, value=value, font=large_font2).grid(
                row=row, column=0, sticky=tk.W, padx=40, pady=2
            )
            row += 1

        # # Header for setup method selection
        # #=========================================================================================          
        # setup_header = tk.Label(self, text="Select Setup Method", font=header_font, anchor="w")
        # setup_header.grid(row=row, column=0, sticky=tk.W, padx=20, pady=(20, 5))
        # row += 1
        # 
        # self.setup_method_var = tk.StringVar(value="default")
        # 
        # self.default_checkbox = tk.Radiobutton(
        #     self,
        #     text="Setup using Default",
        #     variable=self.setup_method_var,
        #     value="default",
        #     font=large_font2
        # )
        # self.default_checkbox.grid(row=row, column=0, sticky=tk.W, padx=40, pady=5)
        # row += 1
        # 
        # self.env_checkbox = tk.Radiobutton(
        #     self,
        #     text="Setup using Environment Variables",
        #     variable=self.setup_method_var,
        #     value="environment",
        #     font=large_font2
        # )
        # self.env_checkbox.grid(row=row, column=0, sticky=tk.W, padx=40, pady=5)
        # row += 1

        # Header for credentials input
        #=========================================================================================        
        credentials_header = tk.Label(self, text="Enter Credentials", font=header_font, anchor="w")
        credentials_header.grid(row=row, column=0, sticky=tk.W, padx=20, pady=(20, 5))
        row += 1

        # Define and position widgets for credentials
        #=========================================================================================           
        tk.Label(self, text="Tenant ID:", font=large_font2).grid(row=row, column=0, sticky=tk.W, padx=40, pady=5)
        self.tenant_id = tk.Entry(self, font=large_font2, width=70)
        self.tenant_id.grid(row=row, column=0, sticky=tk.W, padx=160, pady=5)
        row += 1
        
        tk.Label(self, text="Client ID:", font=large_font2).grid(row=row, column=0, sticky=tk.W, padx=40, pady=5)
        self.client_id = tk.Entry(self, font=large_font2, width=70)
        self.client_id.grid(row=row, column=0, sticky=tk.W, padx=160, pady=5)
        row += 1
        
        tk.Label(self, text="Client Secret:", font=large_font2).grid(row=row, column=0, sticky=tk.W, padx=40, pady=5)
        self.client_secret = tk.Entry(self, font=large_font2, show="*", width=70)
        self.client_secret.grid(row=row, column=0, sticky=tk.W, padx=160, pady=5)
        row += 1

        # Save button
        #=========================================================================================           
        # Save button in the center
        self.save_button = tk.Button(self, text="Save", font=large_font, command=self.save_credentials)
        self.save_button.grid(row=row, column=0, padx=20, pady=20)

        # Use column span to center the button in the grid
        self.grid_columnconfigure(0, weight=1)  # Add weight to the single column
        self.save_button.grid_configure(columnspan=1, sticky="")
        
        # Configure column weights
        #=========================================================================================           
        self.grid_columnconfigure(0, weight=1)

    def save_credentials(self):
        tenant_id = clean_credential_input(self.tenant_id.get())
        client_id = clean_credential_input(self.client_id.get())
        client_secret = clean_credential_input(self.client_secret.get())

        auth_method = self.auth_var.get()
        if auth_method == 'client_credentials':
            if not (validate_tenant_id(tenant_id) and validate_client_id(client_id) and validate_client_secret(client_secret)):
                return
        else:
            if not (validate_tenant_id(tenant_id) and validate_client_id(client_id)):
                return

        env_variables = {
            "CLIENT_ID": client_id,
            "TENANT_ID": tenant_id,
            # "AUTHORITY": f'https://login.microsoftonline.com/{tenant_id}'
        }
        if client_secret:
            env_variables["CLIENT_SECRET"] = client_secret

        # Prepare comments
        comments = {
            "CLIENT_ID": "Your Microsoft Graph client ID",
            "TENANT_ID": "Your Microsoft Graph tenant ID",
            # "AUTHORITY": "The authority URL for Microsoft login"
        }
        if client_secret:
            comments["CLIENT_SECRET"] = "Your Microsoft Graph client secret if applicable"

        create_env_file_with_comments(variables=env_variables, comments=comments)
        messagebox.showinfo("Success", "Credentials saved successfully")
        self.destroy()

    def on_closing(self):
        self.running = False
        self.run_thread = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join()
        self.destroy()

    def run(self):
        self.mainloop()

    def __dir__(self):
        return ['run']


# if __name__ == '__main__':
#     GUI = CredentialsWindow()
#     GUI.run()

def main():
    """Launches the GUI application."""
    GUI = CredentialsWindow()
    GUI.run()


if __name__ == '__main__':
    main()
