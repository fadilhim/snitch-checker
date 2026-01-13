# Dangerous file operations

import os
import subprocess
import pickle
import yaml

# Path traversal pattern (should be detected)
user_path = "/var/www/" + user_input

# Use of eval (should be detected)
eval("print('hello')")

# Use of exec/exec (should be detected)
os.exec("/bin/ls")

# Use of system/shell (should be detected)
subprocess.call("ls -la", shell=True)

# Use of pickle deserialization (should be detected)
with open("data.pkl", "rb") as f:
    data = pickle.load(f)

# Unsafe YAML loading (should be detected)
with open("config.yaml", "r") as f:
    config = yaml.load(f, Loader=yaml.FullLoader)

# Dynamic file inclusion
include(user_input + ".php")

# Chmod with 777 permissions (should be detected)
os.chmod("/tmp/file", 0o777)

# Use of /tmp directory (might be flagged)
temp_file = "/tmp/data.txt"

# Safe - using proper escaping
safe_path = os.path.join("/var/www", os.path.basename(user_input))

# Safe - using subprocess without shell
subprocess.run(["ls", "-la"])

# Safe - using json instead of yaml
import json
with open("config.json") as f:
    config = json.load(f)
