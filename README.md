Operational Technology (OT) / Industrial Control Systems (ICS) Security Toolkit
Module 1 of the Sierra–Einstein–SIRMEN Cyber Defence Platform
OT/ICS Network Discovery and Modbus Scanner (Module 1 of Sierra–Einstein–SiRMEN OT Cyber Defence Platform).
Sierra-1 is a lightweight OT/ICS security toolkit designed for:

OT Network Discovery

Modbus TCP Traffic Monitoring

Modbus Function Code Alerting

Simulated Modbus Server for Testing

Secure Write-Register Testing (Client Tool)

This module provides a client, server, and passive network sniffer for Modbus TCP — the most widely used industrial protocol in SCADA, PLC, and ICS systems.

The tools are built for education, assessment, and blue-team/OT-security validation.
Included Tools
1. modbus_client_write.py

A Modbus TCP write-client that sends values to holding registers on a target PLC/IP.

Used for testing device responses

Helps validate secure configuration

Demonstrates unsafe function codes (FC 6, FC 16)

2. modbus_server.py

A minimalistic Modbus TCP server simulation.

Emulates PLC-like register storage

Allows safe testing without touching real industrial hardware

Useful for labs and demonstrations

3. modbus_monitor.py

A passive Modbus TCP network sniffer with alerting logic.

Sniffs traffic on a specified network interface

Logs Modbus packets to CSV / JSON / text

Alerts on high-risk function codes

Helps detect unauthorized write attempts

This tool demonstrates how threat actors abuse legacy ICS protocols — and how defenders can detect them.
Requirements

Python 3.x

pymodbus

scapy

Root/admin privileges for network sniffing
pip install pymodbus scapy

Usage
Start Modbus Server
sudo python3 modbus_server.py

Run Client Write Tool
python3 modbus_client_write.py

Start Network Monitor
sudo python3 modbus_monitor.py -i <interface>

Purpose

This project is part of a larger OT cyber-defence framework:

Sierra–Einstein–SIRMEN → AI-Driven OT Defence Platform

Module 1 (this repo) focuses on Modbus monitoring, detection, and traffic simulation.

Future modules will add:

ICS anomaly detection

Protocol fuzzing

Advanced AI-driven intrusion detection

Attack-path modelling

Red-team automation

Author

Ian Gracias MSc — OT Security, Cyber Defence & AI Engineering
GitHub: https://github.com/XRPGRACIASXRP

Support the Project

If you find this useful, please star ⭐ the repo.
