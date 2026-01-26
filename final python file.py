import time, serial
from serial.tools import list_ports

BAUD = 115200

def auto_find_esp32_port():
    cands = []
    for p in list_ports.comports():
        desc = f"{p.device} | {p.description} | {p.hwid}".lower()
        if any(x in desc for x in ["cp210", "ch340", "wch", "usb-serial", "esp32", "uart"]):
            cands.append(p.device)
    return cands[-1] if cands else None

port = auto_find_esp32_port()
if not port:
    raise SystemExit("ESP32 port not found")

ser = serial.Serial(port, BAUD, timeout=2)
time.sleep(2)
ser.reset_input_buffer()

print("BOOT:", ser.readline().decode(errors="ignore").strip())

temp = "25.6"
ser.write((temp + "\n").encode())
print("ENC :", ser.readline().decode(errors="ignore").strip())

ser.write(b"__DEC__\n")
print("DEC :", ser.readline().decode(errors="ignore").strip())

ser.close()
