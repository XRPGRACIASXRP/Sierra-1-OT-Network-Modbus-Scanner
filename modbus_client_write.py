from pymodbus.client.sync import ModbusTcpClient
import time

# Modbus client configuration
SERVER_IP = "127.0.0.1"
SERVER_PORT = 5020

client = ModbusTcpClient(SERVER_IP, port=SERVER_PORT)

def write_registers():
    values = [10, 20, 30, 40, 50]

    for i, value in enumerate(values):
        rr = client.write_register(i, value)
        print(f"Written Value {value} to Register {i}")
        time.sleep(1)

if __name__ == "__main__":
    if client.connect():
        print("Connected to Modbus Server")
        write_registers()
        client.close()
    else:
        print("Connection failed")
