import os
from msal import PublicClientApplication, ConfidentialClientApplication
import threading
import re
from dotenv import load_dotenv
import time
import sys
import webbrowser
import logging

# Custom Imports
from .permissions import scope_fmt
from ._configure import konfigurasie
from .tokens import tokentime_fmt, load_token_cache, save_token_cache, resolve_token_path

# Paths
default_env_path = konfigurasie.default_env_path
default_token_path = konfigurasie.default_token_path



# NOTE: If you do not supply a Tenant ID for some authentication flows, you must provide the full authority URL. 
# The Tenant ID is a part of the authority URL used in Microsoft Graph authentication.


def client_secret_valid(secret):
    """
    Validates if the given secret matches the Azure Graph client secret criteria.
    :param secret: The client secret string to validate.
    :return: True if valid, False otherwise.
    """
    return bool(re.match(r"^[a-zA-Z0-9\-_\.~]{1,40}$", secret))




class Authentication:
    """
    Handles authentication and token management for various Azure authentication flows.

    Description:
    ------------
    The `Authentication` class supports multiple methods for authenticating with Azure services. 
    It provides mechanisms to authenticate using client credentials, silent authentication, 
    interactive authentication, and device code flow. Additionally, it offers flexibility in 
    loading credentials from environment variables, `.env` files, or direct input.

    Attributes:
    -----------
    client_id (str): 
        The application (client) ID used for authentication.
    tenant_id (str): 
        The directory (tenant) ID for the Azure Active Directory.
    client_secret (str, optional): 
        The client secret for the application (if applicable).
    authority (str): 
        The authority URL used for authentication.
    default_env_path (str): 
        Path to the default `.env` file for loading credentials.
    default_token_path (str): 
        Path to the default token cache file.
    token_path (str): 
        Path to the token cache file, resolved during initialization.
    scopes (list or str, optional): 
        Scopes requested during authentication.
    token_result_cache (dict): 
        Cache for storing the current token and related information.
    _expires_in (int, private): 
        The remaining time (in seconds) before the current token expires.
    _ext_expires_in (int, private): 
        The extended expiration time (if available).
    _access_token (str, private): 
        The current access token.
    _refresh_token_value (str, private): 
        The current refresh token value.
    _id_token (str, private): 
        The current ID token.
    _token_source (str, private): 
        The source of the current token.
    _iat (int, private): 
        The issued-at timestamp of the token.
    _nbf (int, private): 
        The "not before" timestamp of the token.
    _exp (int, private): 
        The expiration timestamp of the token.

    Methods:
    --------
    Build.Default(authority=None):
        Loads credentials from the default `.env` file and assigns them to the instance.
    Build.WithEntry(client_id, tenant_id, client_secret=None, authority=None):
        Sets credentials directly through parameters and assigns them to the instance.
    Build.WithEnvFile(env_path, key_map=None, authority=None):
        Loads credentials from a specified `.env` file with optional key mapping.
    Build.WithOSEnv(key_map=None, authority=None):
        Fetches credentials from OS environment variables or directly assigned values.
    Silent(scopes=None):
        Performs silent authentication to acquire an access token using cached credentials.
    Interactive(scopes=None):
        Performs interactive authentication to acquire an access token.
    ClientCredentials(scopes=None):
        Authenticates using client credentials to acquire an access token.
    DeviceCodeFlow(scopes=None, webbrowser_enabled=False):
        Authenticates using the device code flow to acquire an access token.
    
    Properties:
    -----------
    access_token:
        Returns the current access token, refreshing it if necessary.
    token_expires_in:
        Calculates the remaining time until the access token expires.
    token_expires_at:
        Returns the static expiration time of the access token.
    token_ext_expires_in:
        Calculates the extended expiration time for the access token.
    refresh_token_value:
        Retrieves the current refresh token value.
    id_token:
        Retrieves the current ID token value.
    token_source:
        Retrieves the source of the token.
    token_issued_at:
        Retrieves the issued-at timestamp of the token.
    token_valid_after:
        Retrieves the "not before" timestamp of the token.
    token_expiration:
        Retrieves the expiration timestamp of the token.

    Notes:
    ------
    This class is designed to streamline authentication with Azure Active Directory and manage tokens 
    for various authentication flows, providing extensibility and ease of use.
    """	
    def __init__(self, scopes=None, token_path=None):
        self.client_id = None
        self.tenant_id = None
        self.client_secret = None
        self.authority = None
        self.default_env_path = default_env_path      
        self.default_token_path = default_token_path      
        self.token_path = resolve_token_path(token_path) or self.default_token_path
        self.scopes = scope_fmt(scopes=scopes) if scopes else None
        self.token_result_cache = {}      
        self.Build = self.Build(self)
        
        # Initialize token-related attributes
        self._expires_in = None
        self._ext_expires_in = None
        self._access_token = None
        self._refresh_token_value = None
        self._id_token = None
        self._token_source = None
        self._iat = None
        self._nbf = None
        self._exp = None

    def _update_internal_state(self):
        if self.token_result_cache:
            self._expires_in = self.token_result_cache.get('expires_in', 3600)
            self._ext_expires_in = self.token_result_cache.get('ext_expires_in', None)
            self._access_token = self.token_result_cache.get('access_token', None)
            self._refresh_token_value = self.token_result_cache.get('refresh_token', None)
            self._id_token = self.token_result_cache.get('id_token', None)
            self._token_source = self.token_result_cache.get('token_source', None)

            # ID token claims
            id_token_claims = self.token_result_cache.get('id_token_claims', {})
            self._iat = id_token_claims.get('iat', int(time.time()))
            self._nbf = id_token_claims.get('nbf', None)
            self._exp = id_token_claims.get('exp', None)

    def _try_refresh(self):
        """ Checks if the token needs refreshing and refreshes it if necessary using the Silent method."""
        remaining_time = self.token_expires_in
        if remaining_time == "Expired" or (isinstance(remaining_time, int) and remaining_time < 300):
            logging.info("Token is about to expire or is expired, attempting to refresh.")
            self.Silent()

    @property
    def access_token(self):
        """Returns the current access token, refreshing it if necessary."""
        self._try_refresh()
        return self._access_token  

    @property    
    def token_expires_in(self):
        """Calculate the remaining time until the access token expires."""
        if self._iat and self._expires_in:
            expiration_time = self._iat + self._expires_in
            remaining_time = expiration_time - int(time.time())
            return remaining_time if remaining_time > 0 else "Expired"
        return None

    @property
    def token_expires_at(self):
        """Calculate the static time the access token expires."""  	
        timestamp = self._expires_in
        issued = self._iat
        return tokentime_fmt(timestamp, start_timestamp=issued)

    @property
    def token_ext_expires_in(self):
        """Calculate the extended expiration time for the access token."""    	
        timestamp = self._ext_expires_in
        issued = self._iat
        return tokentime_fmt(timestamp, start_timestamp=issued)

    @property
    def refresh_token_value(self):
        """Retrieve the current refresh token value."""    	
        return self._refresh_token_value

    @property
    def id_token(self):
        """Retrieve the current ID token value."""    	
        return self._id_token

    @property
    def token_source(self):
        """Retrieve the source of the token."""    	
        return self._token_source

    @property
    def token_issued_at(self):
        """Retrieve the timestamp when the token was issued."""
        timestamp = self._iat
        return tokentime_fmt(timestamp, start_timestamp=None)
        
    @property
    def token_valid_after(self):
        """Retrieve the "not before" timestamp for the token."""
        timestamp = self._nbf
        if timestamp:
            return tokentime_fmt(timestamp, start_timestamp=None)

    @property
    def token_expiration(self):
        """Retrieve the expiration timestamp for the token."""
        timestamp = self._exp 
        if timestamp:
            return tokentime_fmt(timestamp, start_timestamp=None)
            
            
    # Build Credentials
    #------------------------------------------------------------------------------------------------------------------------            
    class Build:
        def __init__(self, auth):
            self.auth = auth
            
        def Default(self, authority=None):
            """
            Loads credentials from the default .env file and assigns them to the class instance.

            Description:
            ------------
            This method reads the `CLIENT_ID`, `TENANT_ID`, and `CLIENT_SECRET` from the default `.env` file
            located at the path specified in the `default_env_path` attribute of the Authentication instance.

            Parameters:
            -----------
            authority (str, optional): The authority URL for authentication. Defaults to None.

            Raises:
            -------
            ValueError:
                If any required variables (`CLIENT_ID`, `TENANT_ID`, or `CLIENT_SECRET`) are missing.

            Returns:
            --------
            Authentication:
                The updated Authentication instance with credentials loaded.
            """
            load_dotenv(self.auth.default_env_path)          
            self.auth.client_id = os.getenv("CLIENT_ID")
            self.auth.tenant_id = os.getenv("TENANT_ID")
            self.auth.client_secret = os.getenv("CLIENT_SECRET")
            self.auth.authority = authority or f"https://login.microsoftonline.com/{self.auth.tenant_id}"
            if not all([self.auth.client_id, self.auth.tenant_id]):
                raise ValueError("Required variables CLIENT_ID and TENANT_ID are missing.")
            logging.info("Credentials Stored")
            return self.auth            
    	
        def WithEntry(self, client_id, tenant_id, client_secret=None, authority=None):
            """
            Sets credentials directly through parameters and assigns them to the class instance.

            Parameters:
            -----------
            client_id (str): 
                The application (client) ID.
            tenant_id (str): 
                The directory (tenant) ID.
            client_secret (str, optional): 
                The client secret. Defaults to None.
            authority (str, optional): 
                The authority URL. Defaults to "https://login.microsoftonline.com/{tenant_id}".

            Raises:
            -------
            ValueError:
                If `client_id` or `tenant_id` are missing.

            Returns:
            --------
            Authentication:
                The updated Authentication instance with the provided credentials.
            """
            if not all([client_id, tenant_id]):
                raise ValueError("All required arguments (client_id, tenant_id) must be provided.")
               
            self.auth.client_id = client_id
            self.auth.tenant_id = tenant_id
            self.auth.client_secret = client_secret
            self.auth.authority = authority or f"https://login.microsoftonline.com/{self.auth.tenant_id}"
            logging.info("Credentials Stored")
            return self.auth            

        def WithEnvFile(self, env_path, key_map=None, authority=None):
            """
            Loads credentials from a specified .env file using a user-defined mapping or defaults, 
            and assigns them to the class instance.

            Parameters:
            -----------
            env_path (str): 
                Path to the .env file.
            key_map (dict, optional): 
                Mapping of class attribute names to environment variable keys.
                Defaults to {"client_id": "CLIENT_ID", "tenant_id": "TENANT_ID", "client_secret": "CLIENT_SECRET"}.
            authority (str, optional): 
                The authority URL for authentication. Defaults to None.

            Raises:
            -------
            FileNotFoundError:
                If the specified .env file does not exist.
            ValueError:
                If any required variables are missing in the .env file.

            Returns:
            --------
            Authentication:
                The updated Authentication instance with credentials loaded from the .env file.
            """
            if not os.path.exists(env_path):
                raise FileNotFoundError(f"The specified .env file does not exist at: {env_path}")

            load_dotenv(env_path)
            
            default_key_map = {
                "client_id": "CLIENT_ID",
                "tenant_id": "TENANT_ID",
                "client_secret": "CLIENT_SECRET"
            }
            key_map = key_map or default_key_map

            credentials = {}
            for attr_name, env_var in key_map.items():
                value = os.getenv(env_var)
                if value is None:
                    raise ValueError(f"Environment variable {env_var} is missing in the .env file.")
                credentials[attr_name] = value

            self.auth.client_id = credentials.get("client_id")
            self.auth.tenant_id = credentials.get("tenant_id")
            self.auth.client_secret = credentials.get("client_secret")
            self.auth.authority = authority or f"https://login.microsoftonline.com/{self.auth.tenant_id}"
            if not all([self.auth.client_id, self.auth.tenant_id]):
                raise ValueError("One or more required variables are missing.")
            logging.info("Credentials Stored")
            return self.auth            

        def WithOSEnv(self, key_map=None, authority=None):
            """
            Fetches credentials from OS environment variables or uses directly assigned values.

            Description:
            ------------
            This method uses a user-defined mapping or defaults to fetch credentials either from
            environment variables or directly provided values. It supports both ordered lists and
            unordered key-value dictionaries.

            Parameters:
            -----------
            key_map (dict or list, optional): 
                A mapping of attribute names to:
                - Environment variable keys (default behavior), or
                - Directly assigned values.
                Examples:
                    {"client_id": "CLIENT_ID", "tenant_id": "TENANT_ID", "client_secret": "CLIENT_SECRET"}
                    ["CLIENT_ID", "TENANT_ID", "CLIENT_SECRET"]
                    ["some-client-id", "some-tenant-id", "some-client-secret"]
            authority (str, optional): 
                The authority URL for authentication. Defaults to None.

            Raises:
            -------
            ValueError:
                If required values are missing or input format is invalid.

            Returns:
            --------
            Authentication:
                The updated Authentication instance with credentials loaded from OS environment variables.
            """
            default_key_map = {
                "client_id": "CLIENT_ID",
                "tenant_id": "TENANT_ID",
                "client_secret": "CLIENT_SECRET"
            }

            if key_map is None:
                key_map = default_key_map

            if isinstance(key_map, list):
                if len(key_map) < 2 or len(key_map) > 3:
                    raise ValueError("List must contain 2 or 3 elements: [client_id, tenant_id, client_secret(optional)].")
                key_map = dict(zip(["client_id", "tenant_id", "client_secret"], key_map))

            key_map = {k: key_map.get(k, None) for k in default_key_map.keys()}

            credentials = {}
            for attr_name, env_or_value in key_map.items():
                if attr_name == 'client_secret' and env_or_value is None:
                    continue

                if env_or_value is None:
                    raise ValueError(f"Key '{attr_name}' is missing in the provided mapping or defaults.")

                if isinstance(env_or_value, str):
                    env_value = os.getenv(env_or_value)
                    value = env_value if env_value is not None else env_or_value
                else:
                    value = env_or_value

                if attr_name == 'client_secret' and not client_secret_valid(value):
                    raise ValueError("The provided 'client_secret' is invalid according to Azure Graph criteria.")

                credentials[attr_name] = value

            self.auth.client_id = credentials.get("client_id")
            self.auth.tenant_id = credentials.get("tenant_id")
            self.auth.client_secret = credentials.get("client_secret", None)
            self.auth.authority = authority or f"https://login.microsoftonline.com/{self.auth.tenant_id}"

            if not all([self.auth.client_id, self.auth.tenant_id]):
                raise ValueError("Required values for 'client_id' and 'tenant_id' are missing.")

            logging.info("Credentials successfully stored.")
            return self.auth


    # Authentication Methods
    #------------------------------------------------------------------------------------------------------------------------
    def Silent(self, scopes=None):
        """
        Performs silent authentication to acquire an access token.

        Description:
        ------------
        This method attempts to acquire a token using cached credentials silently.
        If the token cannot be retrieved or is expired, it falls back to interactive authentication.

        Parameters:
        -----------
        scopes (list or str, optional): 
            Scopes to request. Defaults to the scopes defined in the instance.

        Returns:
        --------
        None: 
            Updates the internal token state or initiates interactive authentication if silent authentication fails.
        """   	
        token_cache = load_token_cache(self.token_path)
        app = PublicClientApplication(authority=self.authority, client_id=self.client_id, token_cache=token_cache)
        accounts = app.get_accounts()
        result = None
        if accounts:
            result = app.acquire_token_silent(scopes or self.scopes, account=accounts[0])
        if result and "access_token" in result:
            self.token_result_cache = result  
            self._update_internal_state()
            logging.info("Silent Authentication Success")
        else:
            logging.warning("Silent Authentication Failed - No valid refresh token, initiating interactive authentication")
            result = self.Interactive(scopes or self.scopes)
        return None        

    def Interactive(self, scopes=None):
        """
        Performs interactive authentication to acquire an access token.

        Description:
        ------------
        This method prompts the user interactively (e.g., in a browser) to log in and acquire a token.
        The token cache is updated upon successful authentication.

        Parameters:
        -----------
        scopes (list or str, optional): 
            Scopes to request. Defaults to the scopes defined in the instance.

        Returns:
        --------
        None: 
            Updates the internal token state after successful authentication.
        """   	
        token_cache = load_token_cache(self.token_path) if self.token_path else None
        app = PublicClientApplication(authority=self.authority, client_id=self.client_id, token_cache=token_cache)
        result = None
        def interactive_auth():
            nonlocal result
            result = app.acquire_token_interactive(scopes or self.scopes)
        
        auth_thread = threading.Thread(target=interactive_auth)
        auth_thread.start()
        auth_thread.join(timeout=10)
        
        if auth_thread.is_alive():
            logging.warning("Authentication timed out.")
            return None            
        else:
            if self.token_path and token_cache:
                save_token_cache(token_cache, self.token_path)
            if result and "access_token" in result:
                self.token_result_cache = result  
                self._update_internal_state()
                logging.info("Interactive Authentication Success")
            else:
                logging.error("Interactive Authentication Failed:", result)
        return None        

    def ClientCredentials(self, scopes=None):
        """
        Authenticates using client credentials to acquire an access token.

        Description:
        ------------
        This method uses the client ID and client secret to acquire a token for server-to-server communication.

        Parameters:
        -----------
        scopes (list or str, optional): 
            Scopes to request. Defaults to the scopes defined in the instance.

        Returns:
        --------
        None: 
            Updates the internal token state after successful authentication.
        """   	
        app = ConfidentialClientApplication(self.client_id, authority=self.authority, client_credential=self.client_secret)
        result = app.acquire_token_for_client(scopes=scopes or self.scopes)
        access_token = result.get("access_token")
        if access_token:
            self.token_result_cache = result
            self._update_internal_state() 
            logging.info("Access token acquired successfully.")
        else:
            logging.error("Failed to acquire access token:", result)
        return None        
    
    def DeviceCodeFlow(self, scopes=None, webbrowser_enabled=False):
        """
        Authenticates using the device code flow to acquire an access token.

        Description:
        ------------
        This method prompts the user to visit a verification URL and enter a user code
        displayed in the terminal or optionally opened in a browser.

        Parameters:
        -----------
        scopes (list or str, optional): 
            Scopes to request. Defaults to the scopes defined in the instance.
        webbrowser_enabled (bool, optional): 
            If True, automatically opens the verification URL in the default browser.

        Returns:
        --------
        None: 
            Updates the internal token state after successful authentication.
        """   	
        app = PublicClientApplication(self.client_id, authority=self.authority)
        flow = app.initiate_device_flow(scopes=scopes or self.scopes)
        if "user_code" not in flow:
            logging.error("Failed to initiate device code flow.")
            return None

        instruction_message = f"Please visit {flow['verification_uri']} and enter the code: {flow['user_code']}"
        
        if webbrowser_enabled:
            webbrowser.open(flow['verification_uri'])
            instruction_message += "\nAutomatically opening the browser to the above URL."
        else:
            instruction_message += "\nPlease manually open the above URL in your browser and enter the code."

        print(instruction_message)
        sys.stdout.flush()

        expires_at = time.time() + flow['expires_in']
        while time.time() < expires_at:
            time.sleep(flow['interval'])
            result = app.acquire_token_by_device_flow(flow)
            if 'access_token' in result:
                self.token_result_cache = result
                self._update_internal_state()
                logging.info("Token acquired successfully!")
                return None                
            elif "error" in result:
                logging.error(f"Failed to acquire token: {result}")
                break
        logging.error("Authentication timed out.")
        return None

    def __dir__(self):
        available_attributes = []       
        available_attributes.extend([
            "Build", "ClientCredentials", "DeviceCodeFlow", "Interactive", "Silent",
            "authority", "client_id", "client_secret", "scopes", "tenant_id", "token_path",
            "token_result_cache",            
        ])
        if self.token_result_cache:
            available_attributes.extend([
                "_try_refresh", "access_token", "token_expires_in", "token_expires_at", "token_ext_expires_in", "refresh_token_value",
                "id_token", "token_source", "token_issued_at", "token_valid_after", "token_expiration",                    
            ])
        return available_attributes

       
       
def __dir__():
    return ['Authentication']

__all__ = ['Authentication']

	
	
