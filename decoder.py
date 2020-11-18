#! /usr/bin/env python3

import argparse
import json
import struct

from binascii import unhexlify
from base64 import b64decode
from io import BytesIO

parser = argparse.ArgumentParser(description="Decode a PSBT")
parser.add_argument("--hex", action="store_true", help="psbt is in hex, not base64")
parser.add_argument("--psbt-types", help="JSON file that contains all of the types in the PSBT")
parser.add_argument("--pset", action="store_true", help="The PSBT is actually for Elements, it's a PSET")
parser.add_argument("psbt", help="psbt to decode")

args = parser.parse_args()

num_inputs = 0
num_outputs = 0

def read_csuint(s):
    size = struct.unpack("<B", s.read(1))[0]
    if size == 253:
        return struct.unpack("<H", s.read(2))[0]
    elif size == 254:
        return struct.unpack("<I", s.read(4))[0]
    elif size == 255:
        return struct.unpack("<Q", s.read(8))[0]
    return size

def read_bitcoin_vec(s):
    size = read_csuint(s)
    return size, s.read(size)

def deser_map(s, scope, count=None):
    c_str = "" if count is None else f"{count} "
    print(f"{scope.upper()} {c_str}MAP")
    while True:
        # Read the key
        key_size, key_data = read_bitcoin_vec(s)
        if key_size == 0:
            # Separator
            print(f"SEPARATOR:\t{key_size}")
            break

        # Read the type
        s_key = BytesIO(key_data)
        rec_type = str(read_csuint(s_key))
        is_tx = False
        if rec_type == "0":
            # Global is always the raw tx. We need to get input and output counts from here
            is_tx = True
            psbt_type = "TX\t"
        elif rec_type in psbt_types[scope]:
            psbt_type = psbt_types[scope][rec_type]
        else:
            psbt_type = "unknown\t"

        # Deal with proprietary types
        if rec_type == "fc":
            prefix_size, prefix_str = read_bitcoin_vec(s_key)
            prefix_str = str(prefix_str)
            subtype = str(read_csuint(s_key))
            prop_maps = psbt_types[scope]["proprietary"]
            prop_type = "unknown"
            if prefix_str in prop_maps:
                prop_map = psbt_types[prefix_str]
                if subtype in prop_map:
                    prop_type = prop_map[subtype]
            psbt_type += f" {prefix_str} {prop_type.upper()}"

        # Read the value
        value_size, value_data = read_bitcoin_vec(s)
        if is_tx:
            s_val = BytesIO(value_data);
            s_val.read(4) # TX Version
            global num_inputs
            global num_outputs
            num_inputs = read_csuint(s_val)

            # Skip the rest to get to the output count
            for _ in range(num_inputs):
                s_val.read(36) # Outpoint
                script_size = read_csuint(s_val)
                s_val.read(script_size) # scriptSig
                s_val.read(4) # Sequence

            num_outputs = read_csuint(s_val)

        # Print these out
        print(f"RECORD:\t\t{psbt_type.upper()}\t{key_size}\t{key_data.hex()}\t{value_size}\t{value_data.hex()}")

if args.hex:
    # Hex decode
    psbt_bytes = unhexlify(args.psbt)
else:
    # Base64 decode
    psbt_bytes = b64decode(args.psbt)

if args.psbt_types is None:
    types_file = "psbttypes.json"
    if args.pset:
        types_file = "psettypes.json"

# Get the PSBT types
psbt_types = {}
with open(types_file) as f:
    psbt_types = json.load(f)

# Do the PSBT stuff now
psbt = BytesIO(psbt_bytes)

# Magic
magic = psbt.read(4)
sep = psbt.read(1)

print(f"MAGIC:\t\t{magic.hex()}\t{magic}")
print(f"SEPARATOR:\t{sep.hex()}\n")

# Global
print("BEGIN GLOBAL")
deser_map(psbt, "global")

# Inputs
print("\nBEGIN INPUTS")
for i in range(num_inputs):
    deser_map(psbt, "input", i)

# Outputs
print("\nBEGIN OUTPUTS")
for i in range(num_outputs):
    deser_map(psbt, "output", i)
