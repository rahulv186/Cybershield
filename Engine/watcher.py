# watcher.py
# File watcher that tails Zeek logs in real time, handling log rotations

import os
import time
import utils

def tail_file(filepath):
    """
    Tails a file, yielding new lines as they are appended.
    Handles log rotation when the file is recreated or truncated.
    """
    f = None
    last_ino = None
    
    utils.debug_log(f"Watchdog starting for path: {filepath}")
    
    while True:
        if not os.path.exists(filepath):
            # File does not exist yet; wait for it to be created
            time.sleep(0.5)
            continue
            
        try:
            st = os.stat(filepath)
            current_ino = st.st_ino
            current_size = st.st_size
            
            if f is None:
                # First open: seek to the end to read only new appends
                f = open(filepath, 'r', encoding='utf-8', errors='ignore')
                f.seek(0, 2)
                last_ino = current_ino
                utils.debug_log(f"Opened {filepath} (inode={current_ino}). Seeking to end.")
            elif current_ino != last_ino or current_size < f.tell():
                # File was rotated (inode changed) or truncated (size shrunk)
                utils.debug_log(f"Log rotation detected on {filepath} (inode change: {last_ino} -> {current_ino}, size={current_size}). Reopening.")
                f.close()
                f = open(filepath, 'r', encoding='utf-8', errors='ignore')
                last_ino = current_ino
        except Exception as e:
            utils.debug_log(f"Error checking status/opening {filepath}: {e}")
            time.sleep(0.5)
            continue
            
        line = f.readline()
        if not line:
            # No new data, wait a bit
            time.sleep(0.1)
            continue
            
        # Ignore comments and Zeek header lines
        if line.startswith("#"):
            continue
            
        yield line
