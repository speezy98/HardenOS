import socket
import platform
import sys
import uuid
import subprocess
def get_ip():
    # méthode fiable : socket UDP (ne dépend pas du hostname)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "unknown"
    finally:
        s.close()
    return ip

def get_hostname():
    return socket.gethostname()

def get_windows_version():
    return platform.platform()

def get_machine_uuid():
    return hex(uuid.getnode())

def detect_windows_type():
    if sys.platform != "win32":
        return "Not Windows"
    try:
        

        # PowerShell moderne (remplace wmic)
        cmd = [
            "powershell",
            "-Command",
            "(Get-CimInstance Win32_OperatingSystem).Caption"
        ]

        output = subprocess.check_output(cmd, text=True).lower()

        if "server" in output:
            return "Windows Server"
        else:
            return "Windows Client"

    except:
        return "Unknown (no PowerShell access)"

def estimate_generation():
    release = platform.release()

    mapping = {
        "7": "Windows 7 (2009–2020)",
        "8": "Windows 8/8.1 (2012–2016)",
        "10": "Windows 10 (2015–2022+)",
        "11": "Windows 11 (2021–present)"
    }

    return mapping.get(release, "Unknown Windows generation")

def main():
    print("\nSYSTEM INFO ")
    print("Hostname:", get_hostname())
    print("IP locale:", get_ip())
    print("UUID machine:", get_machine_uuid())

    if sys.platform == "win32":
        print("\nInfo agent Windows")
        print("Hostname:", get_hostname())
        print("Version:", get_windows_version())
        print("Type:", detect_windows_type())
        print("Génération:", estimate_generation())

if __name__ == "__main__":
    main()