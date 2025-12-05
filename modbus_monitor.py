#!/usr/bin/env python3
"""
Modbus/TCP Monitoring Tool – Phase 3
------------------------------------

Features:
- Sniffs Modbus/TCP traffic on a given interface
- Detects high-risk function codes (e.g. FC 6 – Write Single Register)
- Logs to:
    * Human-readable text log
    * CSV file
    * JSON lines file
- Prints clear alerts to the console

This is Project 1 of the SIERRA OT toolkit.
"""

import argparse
import csv
import json
import logging
import os
from datetime import datetime

from scapy.all import sniff, IP, TCP

MODBUS_DEFAULT_PORT = 502

# Common Modbus function codes (subset)
FUNC_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
}


class ModbusMonitor:
    """
    Modbus/TCP monitor that captures packets and records events
    to text, CSV, and JSONL files.
    """

    def __init__(self, interface: str, port: int, log_file: str):
        self.interface = interface
        self.port = port
        self.log_file = log_file

        # Derive CSV + JSONL filenames from base log_file
        base, ext = os.path.splitext(log_file)
        if not base:
            base = "modbus_monitor"

        self.csv_file = f"{base}.csv"
        self.json_file = f"{base}.jsonl"

        # Prepare CSV writer
        self.csv_fp = open(self.csv_file, mode="a", newline="")
        self.csv_writer = csv.writer(self.csv_fp)
        # Write header once if the file is empty
        if os.stat(self.csv_file).st_size == 0:
            self.csv_writer.writerow(
                [
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "function_code",
                    "function_name",
                    "register",
                    "value",
                    "risk_level",
                    "description",
                ]
            )

        # JSONL just needs a file handle
        self.json_fp = open(self.json_file, mode="a")

    def close(self):
        try:
            self.csv_fp.close()
        except Exception:
            pass
        try:
            self.json_fp.close()
        except Exception:
            pass

    def _log_event(self, event: dict):
        """
        Write the event to CSV + JSONL.
        """
        # CSV row
        self.csv_writer.writerow(
            [
                event.get("timestamp", ""),
                event.get("src_ip", ""),
                event.get("dst_ip", ""),
                event.get("function_code", ""),
                event.get("function_name", ""),
                event.get("register", ""),
                event.get("value", ""),
                event.get("risk_level", ""),
                event.get("description", ""),
            ]
        )
        self.csv_fp.flush()

        # JSONL
        self.json_fp.write(json.dumps(event) + "\n")
        self.json_fp.flush()

    def _parse_modbus(self, payload: bytes):
        """
        Parse minimal Modbus/TCP header from raw payload.

        Modbus/TCP header layout:
        - Transaction ID: 2 bytes
        - Protocol ID:    2 bytes
        - Length:         2 bytes
        - Unit ID:        1 byte
        - Function Code:  1 byte
        """
        if len(payload) < 8:
            return None

        # Function code is at byte offset 7
        func_code = payload[7]

        # Optional: for FC 6 (Write Single Register) we can extract register + value
        register = None
        value = None
        if func_code == 6 and len(payload) >= 12:
            # After function code:
            # Address: 2 bytes, Value: 2 bytes
            # Offset 8–9: register address
            # Offset 10–11: register value
            register = int.from_bytes(payload[8:10], byteorder="big")
            value = int.from_bytes(payload[10:12], byteorder="big")

        return {
            "function_code": func_code,
            "register": register,
            "value": value,
        }

    def process_packet(self, pkt):
        """
        Callback for each captured packet.
        """
        if not (IP in pkt and TCP in pkt):
            return

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        raw = bytes(tcp_layer.payload)
        if not raw:
            return

        parsed = self._parse_modbus(raw)
        if not parsed:
            return

        func_code = parsed["function_code"]
        register = parsed["register"]
        value = parsed["value"]

        func_name = FUNC_CODES.get(func_code, "Unknown / Other")

        timestamp = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        # Decide risk level
        if func_code in (5, 6, 15, 16):
            risk = "HIGH-RISK WRITE"
        else:
            risk = "INFO"

        description = f"Modbus {func_name} (FC={func_code}) from {src_ip} to {dst_ip}"
        if register is not None and value is not None:
            description += f" | Register={register}, Value={value}"

        # Console + text log
        if risk.startswith("HIGH"):
            logging.warning(
                "[ALERT] %s | %s -> %s | FC=%d (%s) | reg=%s val=%s",
                risk,
                src_ip,
                dst_ip,
                func_code,
                func_name,
                register,
                value,
            )
        else:
            logging.info(
                "[INFO] %s -> %s | FC=%d (%s) | reg=%s val=%s",
                src_ip,
                dst_ip,
                func_code,
                func_name,
                register,
                value,
            )

        # Structured event
        event = {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "function_code": func_code,
            "function_name": func_name,
            "register": register,
            "value": value,
            "risk_level": risk,
            "description": description,
        }

        self._log_event(event)

    def run(self):
        """
        Start packet capture on the specified interface and port.
        """
        logging.info(
            "Starting Modbus/TCP monitor on interface '%s', port %d",
            self.interface,
            self.port,
        )
        logging.info("Press Ctrl+C to stop.")

        # BPF filter to capture only Modbus/TCP
        bpf_filter = f"tcp port {self.port}"

        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.process_packet,
                store=False,
            )
        finally:
            self.close()
            logging.info("Monitor stopped. Logs written to: %s / %s / %s",
                         self.log_file, self.csv_file, self.json_file)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Modbus/TCP network monitor (SIERRA OT Project 1)"
    )
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        help="Network interface to monitor (e.g. enp0s3, eth0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=MODBUS_DEFAULT_PORT,
        help=f"Modbus/TCP port to monitor (default: {MODBUS_DEFAULT_PORT})",
    )
    parser.add_argument(
        "-l",
        "--log-file",
        default="modbus_monitor.log",
        help="Path to main text log file",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Configure root logger
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(args.log_file),
            logging.StreamHandler(),
        ],
    )

    monitor = ModbusMonitor(
        interface=args.interface,
        port=args.port,
        log_file=args.log_file,
    )

    try:
        monitor.run()
    except KeyboardInterrupt:
        logging.info("Stopping Modbus monitor. Goodbye.")
    except PermissionError:
        print("\n[ERROR] Permission denied. Try running with sudo:")
        print(f"  sudo ./modbus_monitor.py -i {args.interface}")
    except Exception as e:
        logging.error("Unexpected error: %s", e)


if __name__ == "__main__":
    main()
