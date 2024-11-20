import os
import string
import atexit
import shutil
from random import Random as RandomGenerator
import uuid
import time
import re
import logging


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    handlers=[
        logging.StreamHandler()  # Log to the console
    ]
)

def add_flag_if_available(flag_name, base_flags):
    """
    Add a flag to the base flags if it is available in the `os` module.

    Parameters:
    -----------
    flag_name (str):
        The name of the flag to add.
    base_flags (int):
        The base set of flags.

    Returns:
    --------
    int:
        The updated set of flags with the additional flag if available.
    """	
    return base_flags | getattr(os, flag_name, 0)

# Set file creation flags
base_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
text_file_open_flags = add_flag_if_available('O_NOFOLLOW', base_flags)
binary_file_open_flags = add_flag_if_available('O_BINARY', text_file_open_flags)

class RandomNameGenerator:
    """
    A class for generating random names using a predefined character set.

    Attributes:
    -----------
    characters (str):
        The set of allowed characters for generating random names.

    Methods:
    --------
    random_instance -> RandomGenerator:
        Provides a random generator instance, bound to the process ID.

    __iter__():
        Returns the iterator object itself.

    __next__() -> str:
        Generates and returns the next random name.
    """	
    characters = "abcdefghijklmnopqrstuvwxyz0123456789_"
    @property
    def random_instance(self):
        current_pid = os.getpid()
        if current_pid != getattr(self, '_pid_bound_random', None):
            self._random = RandomGenerator()
            self._pid_bound_random = current_pid
        return self._random

    def __iter__(self):
        return self

    def __next__(self):
        allowed_chars = self.characters
        choose_random = self.random_instance.choice
        random_name = [choose_random(allowed_chars) for _ in range(8)]
        return ''.join(random_name)

def get_user_data_dir():
    """
    Get a directory for storing user data based on the operating system.

    Returns:
    --------
    str:
        The path to the user data directory.

    Raises:
    -------
    Exception:
        If the operating system is unsupported.
    """	
    """Get a directory for storing user data based on the operating system."""
    if os.name == 'nt':  # Windows
        return os.path.expanduser('~\\AppData\\Local')
    elif os.name == 'posix':  # macOS and Linux
        if platform.system() == 'Darwin':  # macOS
            return os.path.expanduser('~/Library/Application Support')
        else:  # Linux
            return os.path.expanduser('~/.local/share')
    else:
        raise Exception("Unsupported operating system.")

def verify_directory(directory):
    """
    Verify that a directory is writable and can be used for storage.

    Parameters:
    -----------
    directory (str):
        The directory path to verify.

    Returns:
    --------
    bool:
        True if the directory is writable, otherwise raises an exception.

    Raises:
    -------
    Exception:
        If the directory cannot be verified after multiple attempts.
    """
    name_generator = RandomNameGenerator()
    for attempt in range(100):  # handle rare collision cases
        temp_name = next(name_generator)
        temp_file_path = os.path.join(directory, temp_name)
        try:
            fd = os.open(temp_file_path, binary_file_open_flags, 0o600)
            os.close(fd)
            os.unlink(temp_file_path)
            return True
        except OSError as e:
            logging.warning(f"Attempt {attempt + 1}: Failed to write to {temp_file_path}, error: {e}")
            if attempt == 99:
                raise Exception(f"Failed to verify directory after multiple attempts: {directory}")

def find_default_user_data_dir():
    """
    Find and verify the default directory for storing user data.

    Returns:
    --------
    str:
        The path to the verified user data directory.

    Raises:
    -------
    Exception:
        If the default user data directory cannot be used.
    """	
    user_data_dir = get_user_data_dir()
    if verify_directory(user_data_dir):
        return user_data_dir
    else:
        raise Exception(f"Directory {user_data_dir} cannot be used.")






# Build User Dir class
#-----------------------------------------------------------------------------
class UserDataDirectory:
    """
    A class for creating and managing user data directories.

    Attributes:
    -----------
    base_user_data_dir (str):
        The base directory where user data directories will be created.
    dirname (str):
        The prefix for the directory name.
    auto_remove (bool):
        Flag to control whether directories are automatically removed on exit.

    Methods:
    --------
    Dir() -> str:
        Creates a user data directory with a unique name and registers it for cleanup if `auto_remove` is True.
    Exists(exists_only: bool = False) -> Union[bool, list, None]:
        Searches for matching directories based on a naming pattern.
    Omit(path: str):
        Deletes a specified user data directory.
    DirFile(filename: str, extension: str, existing: bool = False, overwrite: bool = True) -> str:
        Creates a file with the specified name and extension in a user data directory.
    Clean():
        Removes all user data directories created by this class in the base directory.
    """
    def __init__(self, dirname, auto_remove=True):
        """
        Initializes the UserDataDirectory instance.

        Parameters:
        -----------
        dirname (str):
            The prefix for the directory name.
        auto_remove (bool):
            Whether directories should be automatically removed on exit.
        """
        self.base_user_data_dir = find_default_user_data_dir()
        self.dirname = dirname        
        if not self.base_user_data_dir:
            raise Exception("No user data directory environment variable found.")
        self.auto_remove = auto_remove  # Set auto removal flag

    def Dir(self):
        """
        Creates a user data directory and registers it for cleanup if `auto_remove` is True.

        Returns:
        --------
        str:
            The path of the created user data directory.
        """
        rng = RandomGenerator()
        
        part_a = ''.join(rng.choices(string.ascii_uppercase, k=4)) 
        timestamp_ms = int(time.time() * 1000)                     
        unique_id = uuid.uuid4()                                  
        user_data_dir_name = f"{self.dirname}_{part_a}_{timestamp_ms}_{unique_id}"
        user_data_dir_path = os.path.join(self.base_user_data_dir, user_data_dir_name)
        os.makedirs(user_data_dir_path, exist_ok=True)
        if self.auto_remove:
            atexit.register(self.Omit, user_data_dir_path)
        return user_data_dir_path
       
    def Exists(self, otherdir=None, exists_only=False):
        """
        Searches for directories in the base directory that match a specific pattern.

        Parameters:
        -----------
        otherdir (str):
            Optional. A specific directory name or path to validate and search for.
        exists_only (bool):
            If True, returns whether a matching directory exists. If False, returns matching directory paths.

        Returns:
        --------
        bool:
            True if a matching directory exists and `exists_only` is True; False otherwise.
        list:
            A list of paths to all matching directories if `exists_only` is False.
        None:
            If no matching directories are found and `exists_only` is False.
        """
        pattern = r"^(.*)_[A-Z]{4}_\d{13}_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
        if otherdir:
            directoryname = os.path.basename(otherdir).rstrip('_')
            if not re.match(pattern, directoryname):
                regex = re.compile(rf"^{re.escape(directoryname)}_[A-Z]{{4}}_\d{{13}}_[a-f0-9]{{8}}-[a-f0-9]{{4}}-[a-f0-9]{{4}}-[a-f0-9]{{4}}-[a-f0-9]{{12}}$")
            else:
                regex = re.compile(rf"^{re.escape(directoryname)}$")
        else:
            regex = re.compile(rf"^{self.dirname}_[A-Z]{{4}}_\d{{13}}_[a-f0-9]{{8}}-[a-f0-9]{{4}}-[a-f0-9]{{4}}-[a-f0-9]{{4}}-[a-f0-9]{{12}}$")
        matching_directories = []
        try:
            for dirname in os.listdir(self.base_user_data_dir):
                full_path = os.path.join(self.base_user_data_dir, dirname)
                if regex.match(dirname) and os.path.isdir(full_path):
                    matching_directories.append(full_path)
        except OSError as e:
            logging.error(f"Failed to access {self.base_user_data_dir}: {e}")
            return False if exists_only else None
        if exists_only:
            return bool(matching_directories)
        return matching_directories[0] if len(matching_directories) == 1 else matching_directories or None

    def Omit(self, path):
        """
        Deletes a specified user data directory.

        Parameters:
        -----------
        path (str):
            The path of the user data directory to be deleted.
        """
        shutil.rmtree(path, ignore_errors=True)
        logging.info(f"Temporary directory {path} has been deleted.")
       
    def DirFile(self, filename, extension, existing=False, existing_path=None, overwrite=True):
        """
        Creates a file with a specified name and extension in a user data directory.

        Parameters:
        -----------
        filename (str):
            The name of the file to be created.
        extension (str):
            The file extension, with or without a leading '.'.
        existing (bool, optional):
            Whether to use an existing directory. Defaults to False.
        overwrite (bool, optional):
            Whether to overwrite the file if it exists. Defaults to True.

        Returns:
        --------
        str:
            The full path of the newly created or existing file.
        """
        if existing:
            if existing_path:
                user_data_dir_path = self.Exists(otherdir=existing_path)
            else:
                user_data_dir_path = self.Exists()
                
            if not user_data_dir_path:
                user_data_dir_path = self.Dir()
            elif isinstance(user_data_dir_path, list): 
                user_data_dir_path = user_data_dir_path[0]                            
        else:
            user_data_dir_path = self.Dir()
        
        extension = extension.lstrip('.')
        full_file_path = os.path.join(user_data_dir_path, f"{filename}.{extension}")
        
        if not overwrite and os.path.exists(full_file_path):
            return full_file_path

        with open(full_file_path, 'w') as file:
            pass

        return full_file_path      

                  
    def Clean(self, alldirs=False):
        """
        Removes all user data directories created by this class in the base directory.
        """
        pattern = re.compile(r"^(.*)_[A-Z]{4}_\d{13}_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
        directories = os.listdir(self.base_user_data_dir)

        if alldirs:
            for dir_name in directories:
                if pattern.match(dir_name):
                    path = os.path.join(self.base_user_data_dir, dir_name)
                    if os.path.isdir(path):
                        shutil.rmtree(path, ignore_errors=True)

        for item in directories:
            if item.startswith(self.dirname):
                path = os.path.join(self.base_user_data_dir, item)
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                  
    def __dir__(self):
        """
        Lists the public methods of the class.

        Returns:
        --------
        list:
            The list of public method names.
        """    	
        return ['Dir', 'Exists', 'Omit', 'DirFile', 'Clean']
