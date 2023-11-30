"""
Program written by CyberYom
Written in Python 3.11.6

This program is meant to take a MFT file as input, and parse the MFT file, displaying all the information contained
in the MFT file entry such as x-ways templates will.

Program lives on github.
""" 
import sys
import os
from prettytable import PrettyTable
from datetime import datetime, timedelta
from mftclasses import StandardInfo
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import
from mftclasses import

print("\033[91m" + """
		M   M  FFFFF  TTTTT  
		MM MM  F        T    
		M M M  FFF      T    
		M   M  F        T    
		M   M  F        T    
""" + "\033[92m" + """
AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ  EEEEE  RRRRR  
A   A  NN  N  A   A  L      Y Y      Z    E      R   R 
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR  
A   A  N  NN  A   A  L       Y     Z      E      R R   
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR 
""" + "\033[0m" + "	by CyberYom\n\n")


def firstrun():
    print('Welcome to MFT Analyzer. This tool is designed to parse and display MFT metadata. \nPassing -h will display a help menu.' + '\n\n')

def help():
    print("This tool has a few options available. \n")
    print("For simply parsing an MFT file, pass the location of the MFT file.\n-----./MFTAnalyzer.py C:\Path\To\MFTfile-----\n")
    print("To export your results, use the -o flag.\n-----./MFTAnalyzer.py C:\Path\To\MFTfile -o C:\Desired\Path\To\Results-----\n")
    print("To export your results to a CSV, pass the -csv flag (with the -o flag).\n-----./MFTAnalyzer.py C:\Path\To\MFT -csv -o C:\Desired\Path\To\Results.csv-----\n")

def convert_hex_timestamp_to_datetime(hex_timestamp):
    try:
        decimal_timestamp = int(hex_timestamp, 16)
        
        # Check if the timestamp is too large to be valid
        if decimal_timestamp > 0xFFFFFFFFFFFFFFFF:
            return "Invalid Timestamp"

        windows_epoch_start = datetime(1601, 1, 1)
        microseconds = decimal_timestamp // 10
        converted_datetime = windows_epoch_start + timedelta(microseconds=microseconds)
        return converted_datetime
    except (ValueError, OverflowError):
        return "Invalid Timestamp"


def timestamp_from_hex_dump(hex_dump):
    hex_timestamp = ''.join(hex_dump)
    datetime_obj = convert_hex_timestamp_to_datetime(hex_timestamp)

    if isinstance(datetime_obj, str):
        # If the conversion function returned a string, return it directly
        return datetime_obj
    else:
        # Otherwise, format the datetime object
        return datetime_obj.strftime('%Y-%m-%d %H:%M:%S')



def MFT(argpath, target_bytes, length_bytes):
    outputs = []  # A list to store hex dumps for each occurrence
    try:
        with open(argpath, 'rb') as file:
            file_content = file.read()

            # Search for all occurrences of target_bytes
            offset = 0
            while True:
                offset = file_content.find(target_bytes, offset)
                if offset == -1:
                    break  # No more occurrences found

                # Read bytes from each found location
                file.seek(offset)
                bytes_data = file.read(length_bytes)
                hex_data = [f'{byte:02x}' for byte in bytes_data]
                outputs.append(hex_data)

                offset += len(target_bytes)  # Move to the next position

        if not outputs:
            return ["Target byte sequence not found."]

        return outputs  # Return the list of all hex dumps

    except FileNotFoundError:
        return ['File not found.']
    except IOError:
        return ['Error reading the file.']


def parse_attribute(attr_data):
    attr_type = int.from_bytes(attr_data[0:4], byteorder='little')
    # Add logic to handle different types of attributes
    # This is a placeholder implementation and should be expanded based on the MFT structure
    if attr_type == 0x10:  # Example: $STANDARD_INFORMATION
        return [("Type", "$STANDARD_INFORMATION"), ("Timestamp", "Example Timestamp")]
    elif attr_type == 0x20:
        return [("Type", "$ATTRIBUTE_LIST"), ("x", "x")]
    elif attr_type == 0x30:  # Example: $FILE_NAME
        return [("Type", "$FILE_NAME"), ("File Name", "Example Filename")]
    elif attr_type == 0x40:
        return [("Type", "$OBJECT_ID"), ("x", "x")]
    elif attr_type == 0x60:
        return [("Type", "$VOLUME_NAME"), ("x", "x")]
    elif attr_type == 0x70:
        return [("Type", "VOLUME_INFORMATION"), ("x", "x")]
    elif attr_type == 0x80:
        return [("Type", "$DATA"), ("x", "x")]
    elif attr_type == 0x90:
        return [("Type", "$INDEX_ROOT"), ("x", "x")]
    elif attr_type == 0xA0:
        return [("Type", "$INDEX_ALLOCATION"), ("x", "x")]
    elif attr_type == 0xB0:
        return [("Type", "$BITMAP"), ("x", "x")]
    elif attr_type == 0xC0:
        return [("Type", "$REPARSE_POINT"), ("x", "x")]
    else:
        return [("Type", f"Unknown (0x{attr_type:04X})"), ("Data", "Not parsed")]

def handle_path(providedpath):
    result = ""
    if os.path.exists(providedpath):
        try:
            with open(providedpath, 'rb') as file:
                entry_number = 0
                while True:
                    entry = file.read(1024)  # Assuming 1024 bytes per MFT entry
                    if not entry:
                        break

                    table = PrettyTable()
                    table.field_names = ["Title", "Data"]

                    # Parse the entry and add rows to the table
                    first_attr_offset = int.from_bytes(entry[20:22], byteorder='little')
                    offset = first_attr_offset
                    while offset < 1024:
                        attr_length = int.from_bytes(entry[offset+4:offset+8], byteorder='little')
                        if attr_length == 0:
                            break  # End of attributes or invalid length

                        attr_data = entry[offset:offset+attr_length]
                        parsed_data = parse_attribute(attr_data)

                        for title, data in parsed_data:
                            table.add_row([title, data])

                        offset += attr_length

                    result += f"Entry {entry_number}\n" + table.get_string() + "\n\n"
                    entry_number += 1

        except FileNotFoundError:
            return 'File not found.'
        except IOError as e:
            return f'Error reading the file: {e}'
        except Exception as e:
            return f'An unexpected error occurred: {e}'
    else:
        return 'Provided path does not exist.'
    return result


def output_results(data, outputpath):
    try:
        with open(outputpath, 'w') as file:
            file.write(str(data))
        print(f'Output written to file {outputpath}')
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")

def hex_to_ascii(hex_bytes):
    ascii_str = ''
    for hex_byte in hex_bytes:
        byte_int = int(hex_byte, 16)
        ascii_str += chr(byte_int) if 32 <= byte_int < 127 else '.'
    return ascii_str

# Script Execution
if len(sys.argv) == 1:
    firstrun()
elif '-h' in sys.argv:
    help()
else:
    argpath = sys.argv[1]
    path_output = handle_path(argpath)
    print(path_output)

if '-o' in sys.argv:
    try:
        o_index = sys.argv.index('-o')
        if o_index + 1 < len(sys.argv):
            output_path = sys.argv[o_index + 1]
            output_results(path_output, output_path)
        else:
            print("No output path provided after -o.")
    except ValueError:
        print("Error processing -o argument.")
