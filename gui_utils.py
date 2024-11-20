import portalocker
import os
import logging

def enforce_single_instance(lockfile):
    """
    Enforce a single instance of the application using file locking.

    Parameters:
    - lockfile (str): Path to the lock file used for enforcing single instance.

    Returns:
    - lock: The lock object if the instance is the first one, otherwise None.
    """
    try:
        lock = open(lockfile, 'w')
        portalocker.lock(lock, portalocker.LOCK_EX | portalocker.LOCK_NB)
        return lock
    except portalocker.exceptions.LockException:
        return None

def on_exit(lock, lockfile):
    """
    Cleans up application resources on exit by releasing file locks, closing file descriptors, and 
    removing lockfiles.

    This function first attempts to release the exclusive file lock (if held) and then deletes the lockfile.

    Parameters:
        lock (file): The file object on which the lock was acquired using portalocker.
        lockfile (str): A string representing the path to the lockfile.
    """
    try:
        if lock is not None:
            portalocker.unlock(lock)
            lock.close()
        
        # Remove the lockfile
        os.remove(lockfile)
    except Exception as e:
        logging.error(f"Error removing lockfile: {e}")

        
        
