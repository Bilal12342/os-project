
import os

drive = "G:\\"  
eicar_string = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
for i in range(1, 5):
    file_path = os.path.join(drive, f"eicar_test_{i}.com")
    try:
        with open(file_path, "w") as f:
            f.write(eicar_string)
        print(f"[INFO] Created: {file_path}")
    except Exception as e:
        print(f"[ERROR] {file_path}: {e}")
