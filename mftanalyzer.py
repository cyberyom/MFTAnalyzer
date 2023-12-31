"""
Program written by CyberYom
Written in Python 3.11.6

This program is meant to take a MFT file as input, and parse the MFT file, displaying all the information contained
in the MFT file entry such as x-ways templates will.

Program lives on github.
""" 
from prettytable import PrettyTable
from datetime import datetime, timedelta
import os
import sys
import struct

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
""" + "\033[0m" + "      by CyberYom\n\n")

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

def hex_to_ascii(hex_bytes):
    ascii_str = ''
    for hex_byte in hex_bytes:
        byte_int = int(hex_byte, 16)
        if byte_int == 0:
            ascii_str += ''
        else:
            ascii_str += chr(byte_int) if 32 <= byte_int < 127 else '.'
    return ascii_str

def hex_to_short(hex_str):
    try:
        # Reverse the byte order in the hex string
        reversed_hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

        decimal_value = int(reversed_hex_str, 16)
        
        # Check if the decimal value is too large to fit in a short
        if decimal_value > 32767 or decimal_value < -32768:
            return "Out of range for short"

        return decimal_value
    except (ValueError, OverflowError):
        return "Invalid Hex Value"

def filetime_to_dt(filetime_bytes):
    filetime_int = struct.unpack('<Q', filetime_bytes)[0]
    windows_epoch = datetime(1601, 1, 1)

    return windows_epoch + timedelta(microseconds=filetime_int // 10)

def bytes_to_uint32(hex_str):
    if not isinstance(hex_str, str):
        raise TypeError("Expected hex_str to be a string")

    byte_data = bytes.fromhex(hex_str)
    return int.from_bytes(byte_data, byteorder='little')



def bytes_to_hex(byte_data):
    # Reverse the byte_data list for little-endian order
    byte_data_reversed = byte_data[::-1]

    # Convert each byte to a hex string and concatenate
    hex_string = ''.join(format(int(byte, 16), '02X') for byte in byte_data_reversed if byte != '00')
    return hex_string

def hex_to_uint(hex_str):
    try:
        # Reverse the hexadecimal string in pairs of two characters
        reversed_hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
        
        decimal_value = int(reversed_hex_str, 16)
        
        # Ensure the decimal value is non-negative
        if decimal_value < 0:
            return "Negative value not allowed for uint"

        return decimal_value
    except (ValueError, OverflowError):
        return "Invalid Hex Value"

def bytes_to_uint64(raw_bytes):
    # Ensure that the input has exactly 8 bytes (64 bits)
    if len(raw_bytes) != 8:
        raise ValueError("Input must be exactly 8 bytes long")

    # Use struct.unpack to convert the bytes to a uint64
    uint64_value = struct.unpack('Q', raw_bytes)[0]
    return uint64_value

def bytes_to_decimal(hex_string_list):
    byte_data = bytes.fromhex(''.join(hex_string_list))
    return int.from_bytes(byte_data, byteorder='little')

def residency(hex_dump):
    if len(hex_dump) != 1:
        return "Invalid input length"

    if hex_dump[0] == '00':
        return "Resident"
    elif hex_dump[0] == '01':
        return "Nonresident"
    else:
        return "Invalid residency byte"

def dataflag(hex_dump):
    if len(hex_dump) != 2:
        return "Invalid input length"

    if hex_dump[1] == '01':
        return "Is Compressed"
    elif hex_dump[1] == 'ff':
        return "-"
    elif hex_dump[0] == '40':
        return "Is Encrypted"
    elif hex_dump[0] == '80':
        return "Is Sparse"
    else:
        return "Unknown Attr. data flag bytes"


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

def handle_path(providedpath):
    if os.path.exists(providedpath):
        target_bytes = b'\x46\x49\x4C\x45'
        all_hex_dumps = MFT(providedpath, target_bytes, 1024)

        if all_hex_dumps and all_hex_dumps != ["Target byte sequence not found."]:
            all_tables = ""

            for hex_dump in all_hex_dumps:
                if len(hex_dump) >= 6:
                    print("File:")
                    if b'\x46\x49\x4C\x45' in bytes.fromhex(''.join(hex_dump)):
                        print(Entry_Header(hex_dump))
                        standardinfo_offset = hex_to_short(''.join(hex_dump[20:22])) #grabs the value of net attribute offset and binds to new_offset

                    if bytes.fromhex(''.join(hex_dump[standardinfo_offset:standardinfo_offset+4])) == b'\x10\x00\x00\x00':
                        print('      $Standard Information Attribute')
                        standard_info(hex_dump[standardinfo_offset:])
                        next_offset1 = standardinfo_offset + int(bytes_to_hex(hex_dump[standardinfo_offset+4:standardinfo_offset+8]), 16)

                    if bytes.fromhex(''.join(hex_dump[next_offset1:next_offset1+4])) == b'\x20\x00\x00\x00':
                        print('      $Attribute List Attribute')

                    if bytes.fromhex(''.join(hex_dump[next_offset1:next_offset1+4])) == b'\x30\x00\x00\x00':
                        print('      $File Name Attribute')
                        file_name(hex_dump[])


                else:
                    all_tables += "Hex dump is too short.\n\n"

            return all_tables.rstrip()  # Return all tables as a single string
        else:
            return "Target byte sequence not found." if all_hex_dumps == ["Target byte sequence not found."] else "Hex dump is too short."
    else:
        return 'File not found.'


def Entry_Header(hex_dump):
    print('      Entry Header')
    table = PrettyTable()
    table.field_names = ["Title", "Raw Data", "Data"]

    table.add_row(["Signature", ' '.join(hex_dump[:4]),hex_to_ascii(hex_dump[:4])]) # Use the first 4 bytes for Signature
    table.add_row(["Update Sequence Offset", ' '.join(hex_dump[4:6]), hex_to_short(''.join(hex_dump[4:6]))])
    table.add_row(["Update Sequence Size", ' '.join(hex_dump[6:8]), hex_to_short(''.join(hex_dump[6:8]))])
    table.add_row(["Logfile Sequence Number", ' '.join(hex_dump[8:16]), bytes_to_uint64(bytes.fromhex(''.join(hex_dump[8:16])))])
    table.add_row(["Use/Deletion Count", ' '.join(hex_dump[16:18]), hex_to_short(''.join(hex_dump[16:18]))])
    table.add_row(["Hard-link Count", ' '.join(hex_dump[18:20]), hex_to_short(''.join(hex_dump[18:20]))])
    table.add_row(["Offset to First Attribute", ' '.join(hex_dump[20:22]), hex_to_short(''.join(hex_dump[20:22]))])
    table.add_row(["Flags", ' '.join(hex_dump[22:24]), hex_to_ascii(hex_dump[22:24])])
    table.add_row(["Logical Size of Record", ' '.join(hex_dump[24:28]), hex_to_uint(''.join(hex_dump[24:28]))])
    table.add_row(["Physical Size of Record", ' '.join(hex_dump[28:32]), hex_to_uint(''.join(hex_dump[28:32]))])
    table.add_row(["Base Record", ' '.join(hex_dump[32:40]), bytes_to_uint64(bytes.fromhex(''.join(hex_dump[32:40])))])
    return table.get_string() + "\n\n"

def standard_info(hex_dump):
    table = PrettyTable()
    table.field_names = ["Title", "Raw Data", "Data"] #the tables start with generic attr header
    table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Standard Information"])
    table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), bytes_to_hex(hex_dump[4:8])])
    table.add_row(["Attribute Residency", ' '.join(hex_dump[8:9]), residency(hex_dump[8:9])])
    table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
    table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), hex_to_short(''.join(hex_dump[10:12]))])
    table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), dataflag(hex_dump[12:14])])
    table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), hex_to_short(''.join(hex_dump[14:16]))])
    #end of shared attr header
    table.add_row(["File Creation",' '.join(hex_dump[24:32]), filetime_to_dt(bytes([int(b, 16) for b in hex_dump[24:32]]))])
    table.add_row(["File Modification",' '.join(hex_dump[32:40]), filetime_to_dt(bytes([int(b, 16) for b in hex_dump[32:40]]))])
    table.add_row(["MFT Modification",' '.join(hex_dump[40:48]), filetime_to_dt(bytes([int(b, 16) for b in hex_dump[40:48]]))])
    table.add_row(["File Accessed",' '.join(hex_dump[48:56]), filetime_to_dt(bytes([int(b, 16) for b in hex_dump[48:56]]))])
    table.add_row(["Attribute Flags", ' '.join(hex_dump[56:60]), bytes_to_hex(hex_dump[56:60])])   #needs a function to parse flags. Check documentation
    table.add_row(["Max Versions", ' '.join(hex_dump[60:64]), "Unknown"])
    table.add_row(["Version Number", ' '.join(hex_dump[64:68]), "Unknown"])
    table.add_row(["Class Identifier", ' '.join(hex_dump[68:72]), "Unknown"])
    table.add_row(["Owner Identifier", ' '.join(hex_dump[72:76]), "Unknown"])
    table.add_row(["Security Identifier", ' '.join(hex_dump[76:80]), bytes_to_decimal(hex_dump[76:80])])
    table.add_row(["Quota Charged", ' '.join(hex_dump[80:88]), "Unknown"])
    table.add_row(["Update Sequence Number", ' '.join(hex_dump[88:96]), "Unknown"])
    print(table)


def attirbute_list(hex_dump):
    print('      $Attribute List Attribute')
    table = PrettyTable()
    table.field_names = ["Title", "Raw Data", "Data"]
    table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Attribute List"])
    table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), bytes_to_hex(hex_dump[4:8])])
    table.add_row(["Attribute Residency", ' '.join(hex_dump[8:9]), residency(hex_dump[8:9])])
    table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
    table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), hex_to_short(''.join(hex_dump[10:12]))])
    table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), dataflag(hex_dump[12:14])])
    table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), hex_to_short(''.join(hex_dump[14:16]))])

    print(table)

def file_name(hex_dump):
    print('      $Attribute List Attribute')
    table = PrettyTable()
    table.field_names = ["Title", "Raw Data", "Data"]
    table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$File Name"])
    table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), bytes_to_hex(hex_dump[4:8])])
    table.add_row(["Attribute Residency", ' '.join(hex_dump[8:9]), residency(hex_dump[8:9])])
    table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
    table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), hex_to_short(''.join(hex_dump[10:12]))])
    table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), dataflag(hex_dump[12:14])])
    table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), hex_to_short(''.join(hex_dump[14:16]))])

    print(table)

def output_results(data, outputpath):
    try:
        with open(outputpath, 'w') as file:
            file.write(data)
        print(f'Output written to file {outputpath}')
    except IOError as e:
        print(f"An error occurred while writing to the file: {e}")

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
