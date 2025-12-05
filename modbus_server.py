from pymodbus.server.sync import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

def initialize_server():
    # Initial register values
    store = ModbusSlaveContext(
        hr=ModbusSequentialDataBlock(0, [0] * 100)
    )
    context = ModbusServerContext(slaves=store, single=True)

    # Device identity (optional)
    identity = ModbusDeviceIdentification()
    identity.VendorName  = 'Sierra-Einstein OT Platform'
    identity.ProductCode = 'SI-OT'
    identity.ProductName = 'Modbus Simulation Server'
    identity.ModelName   = 'Sierra-1'
    identity.MajorMinorRevision = '1.0'

    # Start server
    print("Modbus Server running on port 5020...")
    StartTcpServer(context, identity=identity, address=("0.0.0.0", 5020))

if __name__ == "__main__":
    initialize_server()
