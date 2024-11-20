import re
import datetime
import os
from tempfile import NamedTemporaryFile
import shutil
from msal import SerializableTokenCache
import logging


def load_token_cache(token_path):
    cache = SerializableTokenCache()
    if not os.path.isfile(token_path):
        logging.warning(f"Token cache file not found at {token_path}. Using a new cache.")
        save_token_cache(cache) 
        return cache
    try:
        with open(token_path, 'r') as f:
            cache_contents = f.read()
        cache.deserialize(cache_contents)
    except IOError as e:
        logging.error(f"Failed to read the token cache file: {e}")
        save_token_cache(cache)
    except Exception as e:
        logging.error(f"Failed to deserialize the token cache: {e}")
        save_token_cache(cache)
    return cache

def save_token_cache(cache, cache_path):
    if not hasattr(cache, 'serialize'):
        logging.error("Cache object must have a 'serialize' method")
    if not isinstance(cache_path, str):
        logging.error("cache_path must be a string")
    try:
        with NamedTemporaryFile('w', delete=False) as tmp_file:
            tmp_file.write(cache.serialize())
            tmp_path = tmp_file.name
        shutil.move(tmp_path, cache_path)
        logging.info(f"Token cache successfully saved to {cache_path}")
    except (IOError, AttributeError) as e:
        logging.error(f"Failed to save token cache: {e}")
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")   

def resolve_token_path(path):
    """Resolve token path, check if it's a directory and find a JSON file."""
    if path is None:
        return None
    
    if os.path.isdir(path):
        try:
            directory_contents = os.listdir(path)
        except PermissionError:
            logging.error(f"Permission denied when accessing directory: {path}")
            return None
        
        json_files = [file for file in directory_contents if file.endswith('.json')]
        if json_files:
            return os.path.join(path, json_files[0])
        else:
            logging.warning(f"No JSON files found in directory: {path}")
            return None
    elif os.path.isfile(path):
        return path
    else:
        logging.error(f"The provided token path does not exist: {path}")
        return None
    return path

def is_valid_JWT(token):
    """ Validates whether the provided token matches the structure of a JSON Web Token (JWT)."""
    return bool(re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$', token))

def tokentime_fmt(timestamp, start_timestamp=None):
    """ Converts a UNIX epoch timestamp to a formatted string."""
    def is_timestamp(value):
        try:
            lower_bound = datetime.datetime.today().year - 5
            upper_bound = datetime.datetime.today().year + 5
            dt = datetime.datetime.fromtimestamp(value)
            if datetime.datetime(lower_bound, 1, 1) <= dt <= datetime.datetime(upper_bound, 1, 1):
                return True
        except (ValueError, OverflowError):
            pass
        return False    
       
    if timestamp is None or isinstance(timestamp, str) and timestamp.lower() == "expired":
        return None        
    if not isinstance(timestamp, int):
        return None
    if not is_timestamp(timestamp):
        start = datetime.datetime.fromtimestamp(start_timestamp)
        return (start + datetime.timedelta(seconds=timestamp)).strftime("%Y-%m-%d %I:%M:%S %p")
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %I:%M:%S %p")

