#!/usr/bin/env python3
# Copyright 2019 Belma Turkovic
# TU Delft Embedded and Networked Systems Group.
# NOTICE: THIS FILE IS BASED ON https://github.com/p4lang/tutorials/tree/master/exercises/p4runtime, BUT WAS MODIFIED UNDER COMPLIANCE
# WITH THE APACHE 2.0 LICENCE FROM THE ORIGINAL WORK.
import argparse
import json
import grpc
import os
import sys
from time import sleep
from threading import Thread
import time

# Flask imports for HTTP server
from flask import Flask, jsonify

# Scappy imports to support packet parsing. 
from scapy.all import (
    Ether,
)

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../util/"))
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../util/lib/"))
import util.lib.p4_cli.bmv2 as bmv2
from util.lib.p4_cli.switch import ShutdownAllSwitchConnections
from util.lib.p4_cli.convert import encodeNum
import util.lib.p4_cli.helper as helper


def printGrpcError(e):
    print("gRPC Error:", e.details(), end="")
    status_code = e.code()
    print("(%s)" % status_code.name, end="")
    traceback = sys.exc_info()[2]
    print("[%s:%d]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno))


# Global variable to store smac list for HTTP server access
smac_table = []
s1_global = None
p4info_helper_global = None

app = Flask(__name__)


def mac_to_index(mac_address):
    """
    Convert MAC address to register index (using lower 8 bits).
    
    :param mac_address: MAC address string (e.g., "00:00:00:00:00:01" or "00-00-00-00-00-01")
    :return: Register index (0-255)
    """
    # Remove colons or dashes and get last byte
    mac_clean = mac_address.replace(':', '').replace('-', '')
    last_byte = int(mac_clean[-2:], 16)
    return last_byte

@app.route('/api/get_hosts', methods=['GET'])
def get_hosts():
    """
    Returns all MAC addresses currently in the smac table.
    """
    return jsonify({
        'hosts': smac_table,
        'count': len(smac_table)
    })

@app.route('/api/set_rate_limit/<mac_address>/<int:new_count>', methods=['GET'])
def set_rate_limit(mac_address, new_count):
    """
    Sets packet count for a specific MAC address.
    Converts MAC address to register index using lower 8 bits.
    """
    global s1, p4info_helper
    
    if s1 is None or p4info_helper is None:
        return jsonify({
            'error': 'Switch connection not established'
        }), 500
    
    print(f"Setting packet count for MAC {mac_address} to {new_count}")
    try:
        table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.threshold_table",
                        match_fields={"hdr.ethernet.srcAddr": mac_address},
                        default_action=False,
                        action_name="MyIngress.rate_limit",
                        action_params={"rate": new_count})
        s1.WriteTableEntry(table_entry)

        return jsonify({
            'mac': mac_address,
            'rate_limit': new_count,
            'status': 'configured'
        })
    except Exception as e:
        print(e)
        return jsonify({
            'error': str(e)
        }), 500

@app.route('/api/unset_rate_limit/<mac_address>', methods=['GET'])
def unset_rate_limit(mac_address):
    """
    Sets packet count for a specific MAC address.
    Converts MAC address to register index using lower 8 bits.
    """
    global s1, p4info_helper
    
    if s1 is None or p4info_helper is None:
        return jsonify({
            'error': 'Switch connection not established'
        }), 500
    
    print(f"Deleting rate limit for MAC {mac_address}")
    try:
        table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.threshold_table",
                        match_fields={"hdr.ethernet.srcAddr": mac_address},
                        default_action=False,
                        action_name="MyIngress.rate_limit",
                        action_params={"rate": 0})
        s1.DeleteTableEntry(table_entry)

        return jsonify({
            'mac': mac_address,
            'status': 'removed'
        })
    except Exception as e:
        print(e)
        return jsonify({
            'error': str(e)
        }), 500

def run_http_server(port=5000):
    """
    Run the Flask HTTP server in a separate thread.
    """
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)


def main(p4info_file_path, bmv2_file_path, config_file_path='mininet/s1-runtime.json'):
    global smac_table, s1, p4info_helper   
    
    # Start HTTP server in a separate thread
    http_thread = Thread(target=run_http_server, args=(8080,), daemon=True)
    http_thread.start()
    print("HTTP server started on http://0.0.0.0:8080")
    
    # Instantiate a P4Runtime helper from the p4info file. This allows you to convert table and field names into integers which make sense for the GRPC API. 
    p4info_helper = helper.P4InfoHelper(p4info_file_path)

    if not os.path.exists(config_file_path):
        print("Runtime config file %s not found!" % config_file_path)
        return
    
    config = json.load(open(config_file_path))

    try:
        # Create a switch connection object for s1;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        
        s1 = bmv2.Bmv2SwitchConnection(
            name="s1",
            address="127.0.0.1:50001",
            device_id=1,
            proto_dump_file="p4runtime.log",
        )

        # Step 1: Establish gRPC connection and set master arbitration update
        # This step establishes this controller as
        # master (required by P4Runtime before performing any other write operation)
        try:
            MasterArbitrationUpdate = s1.MasterArbitrationUpdate()
            print(MasterArbitrationUpdate)
            if MasterArbitrationUpdate == None:
                print("Failed to establish the connection")
        except grpc.RpcError as e:
            if "already used" in str(e):
                print("Error: Election ID already in use by another controller")
                print("Try: 1) Wait and retry  2) Restart the switch  3) Kill competing processes")
                raise
            else:
                raise

        # Step 2: Install the P4 program on the switches
        try:
            s1.SetForwardingPipelineConfig(
                p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path
            )
            print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        except Exception as e:
            print("Forwarding Pipeline added.")
            print(e)
            # Forward all packet to the controller (CPU_PORT 255)

        if "multicast_group_entries" in config:
            for mcentry in config["multicast_group_entries"]:
                entry = p4info_helper.buildMCEntry(mcentry["multicast_group_id"], mcentry["replicas"])
                s1.WritePREEntry(entry)
                print(f"Added multicast group entry: {mcentry}")

        smac = smac_table
        while True:
            print("Listening for packets...")
            packetin = s1.PacketIn()  # Packet in!
            print("Got packet in")
            if packetin is not None:
                print(f"PACKET IN received: {str(packetin)}")
                data = packetin.packet.payload
                print(packetin.packet.metadata)
                port = int.from_bytes(packetin.packet.metadata[1].value, byteorder='big')

                print("Packet bytes: %s" % len(data))
                a = Ether(bytes(data))
                print(data)
                print(f"Received packet: {a.summary()}, port: {port}")

                if a is None or not isinstance(a, Ether):
                    print("Warning: No Ethernet header found")
                    continue

                if a.src not in smac:

                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.smac",
                        match_fields={"hdr.ethernet.srcAddr": a.src},
                        default_action=False,
                        action_name="NoAction",
                        action_params={})
                    s1.WriteTableEntry(table_entry)

                    print(f"Added source MAC {a.src} to smac table")

                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.dmac",
                        match_fields={"hdr.ethernet.dstAddr": a.src},
                        default_action=False,
                        action_name="MyIngress.forward",
                        action_params={"egress_port": port},)
                    s1.WriteTableEntry(table_entry) 
                    smac.append(a.src)
                    smac_table.append(a.src)

                    packetout = p4info_helper.buildPacketOut(payload=a.build(), metadata={1: encodeNum(0, 7), 2: encodeNum(port, 9)})
                    s1.PacketOut(packetout)
                else:
                    print(f"Source MAC {a.src} already in smac table")

    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="P4Runtime Controller")
    parser.add_argument(
        "--p4info",
        help="p4info proto in text format from p4c",
        type=str,
        action="store",
        required=False,
        default="./p4src/build/p4info.txt",
    )
    parser.add_argument(
        "--bmv2-json",
        help="BMv2 JSON file from p4c",
        type=str,
        action="store",
        required=False,
        default="./p4src/build/bmv2.json",
    )
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file %s not found!" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file %s not found!" % args.bmv2_json)
        parser.exit(2)
    main(args.p4info, args.bmv2_json)