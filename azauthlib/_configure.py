import re
import base64
import os
import logging

# Custom Imports
from .appdata import UserDataDirectory

class hull:
    class bool:
        @staticmethod
        def bytes(s):
            """ base64 """
            if len(s) % 4 != 0:
                return False
            if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
                return False
            try:
                decoded_bytes = base64.b64decode(s, validate=True)
                decoded_str = decoded_bytes.decode('utf-8')
                return True
            except (base64.binascii.Error, UnicodeDecodeError):
                return False
        @staticmethod
        def bin(s):
            """ Binary """
            if not all(c in '01' for c in s):
                return False
            if len(s) % 8 != 0:
                return False
            try:
                bytes_list = [s[i:i+8] for i in range(0, len(s), 8)]
                decoded_chars = [chr(int(byte, 2)) for byte in bytes_list]
                decoded_str = ''.join(decoded_chars)
                return True
            except ValueError:
                return False
    class format:
        @staticmethod
        def chr(data, call):
            """ base64 """
            if call == "unformat":
                if not hull.bool.bytes(data):
                    return base64.b64encode(data.encode('utf-8')).decode('utf-8')
            elif call == "format":
                if hull.bool.bytes(data):
                    try:
                        return base64.b64decode(data).decode('utf-8')
                    except (base64.binascii.Error, UnicodeDecodeError):
                        raise ValueError("Invalid base64 input.")
            else:
                raise ValueError("Invalid call. Use 'unformat' or 'format'.")
        @staticmethod
        def str(data, call):
            """ Binary """
            if call == "unformat":
                if not hull.bool.bin(data):
                    return ''.join(format(ord(char), '08b') for char in data)
            elif call == "format":
                if hull.bool.bin(data):
                    try:
                        chars = [chr(int(data[i:i+8], 2)) for i in range(0, len(data), 8)]
                        return ''.join(chars)
                    except ValueError:
                        raise ValueError("Invalid binary input.")
            else:
                raise ValueError("Invalid call. Use 'unformat' or 'format'.")               
    class type:
        @staticmethod
        def map(s, add=None, ret=False):
            formatted = hull.format.chr(s, "format")
            str_formatted = formatted
            if add:
                str_formatted += add
            unformatted = hull.format.chr(str_formatted, "unformat")

            if ret:
                return hull.format.chr(unformatted, "format")
            return unformatted



class SensitieweWaarde:
    def __init__(self, value):
        self._value = hull.format.chr(value, "format")        

    def get(self):
        """
        Return the actual value.
        """
        return self._value

    def __repr__(self):
        """
        Mask the value when printing or representing the object.
        """
        return "<Sensitief>"

    def __str__(self):
        """
        Mask the value when converting to string.
        """
        return "<Sensitief>"

# class _Load:
#     def __init__(self, file_path):
#         self.file_path = file_path
#         self.variables = {}
#         self.load_config()
# 
#     def load_config(self):
#         """
#         Load configuration variables from a file and assign them as instance attributes.
#         """
#         try:
#             with open(self.file_path, "r") as file:
#                 for line in file:
#                     line = line.strip()
#                     if "=" in line:
#                         key, value = line.split("=", 1)
#                         key = key.strip()
#                         value = value.strip().strip('"')
#                         sensitive_value = SensitieweWaarde(value)
#                         self.variables[key] = sensitive_value
#                         setattr(self, key, sensitive_value)
#         except FileNotFoundError:
#             logging.error(f"Error: The file '{self.file_path}' does not exist.")
#         except Exception as e:
#             logging.error(f"An error occurred: {e}")
# 
#     def get_variable(self, key):
#         """
#         Retrieve the SensitieweWaarde object of a configuration variable by key.
#         """
#         return getattr(self, key, None)


class _Load:       
    def __init__(self, file_name):
        module_dir = os.path.dirname(__file__)
        self.file_path = os.path.join(module_dir, file_name)
        self.variables = {}
        self.load_config()

    def load_config(self):
        """
        Load configuration variables from a file and assign them as instance attributes.
        """
        try:
            with open(self.file_path, "r") as file:
                for line in file:
                    line = line.strip()
                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"')
                        sensitive_value = SensitieweWaarde(value)
                        self.variables[key] = sensitive_value
                        setattr(self, key, sensitive_value)
        except FileNotFoundError:
            logging.error(f"Error: The file '{self.file_path}' does not exist.")
        except Exception as e:
            logging.error(f"An error occurred: {e}")

    def get_variable(self, key):
        """
        Retrieve the SensitieweWaarde object of a configuration variable by key.
        """
        return getattr(self, key, None)



class SetPaths:
    """
    Manages paths for user data, credentials, tokens, and environment files.

    Attributes:
    -----------
    cred_dirname (str): Directory name for storing credentials.
    tk_dirname (str): Directory name for storing tokens.

    Methods:
    --------
    get_credentials_path() -> str:
        Retrieves or creates the path for credentials and returns the path to the environment file.
    get_default_token_path() -> str:
        Retrieves or creates the path for token storage and returns the path to the token file.
    """
    def __init__(self, cred_dirname, tk_dirname):
        """
        Initializes the SetPaths with directory names for credentials and tokens.

        Parameters:
        -----------
        cred_dirname (str): The name of the directory to store credentials.
        tk_dirname (str): The name of the directory to store tokens.
        """
        if isinstance(cred_dirname, SensitieweWaarde) and isinstance(tk_dirname, SensitieweWaarde):
            self.cred_dirname = cred_dirname
            self.tk_dirname = tk_dirname
            self.default_env_path = self.get_credentials_path()
            self.default_token_path = self.get_default_token_path()

    def get_credentials_path(self):
        """
        Initializes or finds the credentials directory and prepares the path for the environment file.
        """
        creds_dir = UserDataDirectory(dirname=self.cred_dirname.get(), auto_remove=False)
        credentials_path = creds_dir.Exists()
        if credentials_path:
            return os.path.join(credentials_path, '.env')
        return None

    def get_default_token_path(self):
        """
        Initializes or finds the token directory and prepares the path for the token file.
        """
        token_dir = UserDataDirectory(dirname=self.tk_dirname.get(), auto_remove=False)
        default_token_dir = token_dir.Dir() if not token_dir.Exists() else token_dir.Exists()
        if default_token_dir:
            return token_dir.DirFile(filename='token', extension='.json', existing=True, existing_path=default_token_dir, overwrite=False)
        return None



_config = _Load("_def.py")
cred_dirname = _config.get_variable("crd")
tk_dirname = _config.get_variable("tkn")
konfigurasie = SetPaths(cred_dirname, tk_dirname)    


def __dir__():
    return ['konfigurasie']

__all__ = ['konfigurasie']





