"""
Program written by CyberYom
Written in Python 3.11.6

This program is meant to take a MFT file as input, and parse the MFT file, displaying all the information contained
in the MFT file entry such as x-ways templates will.

Program lives on github.
""" 
from prettytable import PrettyTable
from mfttemplate import tablecreation
from mfttemplate import logic
import os
import sys


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
    print("For simply parsing an MFT file, pass the location of the MFT file.\n-----./MFTAnalyzer.py C:\\Path\\To\\MFTfile-----\n")
    print("To export your results, use the -o flag.\n-----./MFTAnalyzer.py C:\\Path\\To\\MFTfile -o C:\\Desired\\Path\\To\\Results-----\n")
    print("To export your results to a CSV, pass the -csv flag (with the -o flag).\n-----./MFTAnalyzer.py C:\\Path\\To\\MFT -csv -o C:\\Desired\\Path\\To\\Results.csv-----\n")

def MFT(argpath, target_bytes):
    outputs = []  # A list to store hex dumps for each occurrence
    try:
        with open(argpath, 'rb') as file:
            file_content = file.read()
            offset = 0
            while True:
                start_offset = file_content.find(target_bytes, offset)
                if start_offset == -1:
                    break  # No more occurrences found
                logical_size_bytes = file_content[start_offset+24:start_offset+28]
                logical_size = int.from_bytes(logical_size_bytes, byteorder='little')
                entry_end = start_offset + logical_size
                bytes_data = file_content[start_offset:entry_end]
                hex_data = [f'{byte:02x}' for byte in bytes_data]
                outputs.append(hex_data)
                offset = entry_end
        if not outputs:
            return ["No MFT entries found."]
        return outputs  # Return the list of all hex dumps
    except FileNotFoundError:
        return ['File not found.']
    except IOError:
        return ['Error reading the file.']

def determine_attribute_type(hex_dump, offset):
    if offset + 4 > len(hex_dump):
        return "Unknown"
    attr_type_hex = ''.join(hex_dump[offset:offset+4])
    attr_type_int = int(attr_type_hex, 16)
    attr_type_map = {
        0x10000000: '$tablecreation.standard_infoRMATION',
        0x20000000: '$ATTRIBUTE_LIST',
        0x30000000: '$FILE_NAME',
        0x40000000: '$OBJECT_ID',
        0x50000000: '$SECURITY_DESCRIPTOR',
        0x60000000: '$VOLUME_NAME',
        0x70000000: '$VOLUME_INFORMATION',
        0x80000000: '$DATA',
        0x90000000: '$INDEX_ROOT',
        0xa0000000: '$INDEX_ALLOCATION',
        0xb0000000: '$BITMAP',
        0xc0000000: '$REPARSE_POINT',
        0xd0000000: '$EA_INFORMATION',
        0xe0000000: '$EA',
        0xf0000000: '$PROPERTY_SET',
        0x00100000: '$LOGGED_UTILITY_STREAM',
    }
    return attr_type_map.get(attr_type_int, "Unknown")

def update_offset(hex_dump, current_offset):
    if current_offset + 8 > len(hex_dump):
        return len(hex_dump)  # End of the hex dump
    logic_instance = logic()
    attr_length_hex = logic_instance.bytes_to_decimal(hex_dump[current_offset+4:current_offset+8])
    return current_offset + attr_length_hex

def handle_path(providedpath):
    if os.path.exists(providedpath):
        target_bytes = b'\x46\x49\x4C\x45'  # FILE signature
        all_hex_dumps = MFT(providedpath, target_bytes)
        if not all_hex_dumps or all_hex_dumps == ["No MFT entries found."]:
            return "No MFT entries found."
        all_tables = ""
        for hex_dump in all_hex_dumps:
            logic_instance = logic()
            entry_table = tablecreation.Entry_Header(hex_dump[0:]) 
            logical_size = logic_instance.hex_to_uint(''.join(hex_dump[24:28]))
            current_offset = logic_instance.hex_to_short(''.join(hex_dump[20:22]))
            previous_offset = None
            while current_offset < len(hex_dump) and current_offset < logical_size:
                if current_offset == previous_offset:
                    break
                attr_type = determine_attribute_type(hex_dump, current_offset)
                if attr_type != "Unknown":
                    offset_info = f"    Attribute Type: {attr_type}, Current Offset: {current_offset} \n"
                    entry_table += offset_info
                    tablecreation_instance = tablecreation()
                    if attr_type == 'STANDARD_INFORMATION':
                        entry_table += tablecreation_instance.standard_info(hex_dump[current_offset:])
                    elif attr_type == '$ATTRIBUTE_LIST':
                        entry_table += tablecreation_instance.attirbute_list(hex_dump[current_offset:])
                    elif attr_type == '$FILE_NAME':
                        entry_table += tablecreation_instance.file_name(hex_dump[current_offset:])
                    elif attr_type == '$VOLUME_VERSION':
                        entry_table += tablecreation_instance.volume_version(hex_dump[current_offset:])
                    elif attr_type == '$OBJECT_ID':
                        entry_table += tablecreation_instance.object_id(hex_dump[current_offset:])
                    elif attr_type == '$SECURITY_DESCRIPTOR':
                        entry_table += tablecreation_instance.security_descriptor(hex_dump[current_offset:])
                    elif attr_type == "$VOLUME_NAME":
                        entry_table += tablecreation_instance.volume_name(hex_dump[current_offset:])
                    elif attr_type == '$VOLUME_INFORMATION':
                        entry_table += tablecreation_instance.volume_information(hex_dump[current_offset:])
                    elif attr_type == '$DATA':
                        entry_table += tablecreation_instance.data(hex_dump[current_offset:])
                    elif attr_type == '$INDEX_ROOT':
                        entry_table += tablecreation_instance.index_root(hex_dump[current_offset:])
                    elif attr_type == '$INDEX_ALLOCATION':
                        entry_table += tablecreation_instance.index_allocation(hex_dump[current_offset:])
                    elif attr_type == '$BITMAP':
                        entry_table += tablecreation_instance.bitmap(hex_dump[current_offset:])
                    elif attr_type == '$SYMBOLIC_LINK':
                        entry_table += tablecreation_instance.symbolic_link(hex_dump[current_offset])
                    elif attr_type == '$REPARSE_POINT':
                        entry_table += tablecreation_instance.reparse_point(hex_dump[current_offset:])
                    elif attr_type == '$EA_INFORMATION':
                        entry_table =+ tablecreation_instance.ea_information(hex_dump[current_offset])
                    elif attr_type == '$EA':
                        entry_table += tablecreation_instance.ea(hex_dump[current_offset:])
                    elif attr_type == 'PROPERTY_SET':
                        entry_table += tablecreation_instance.property_set(hex_dump[current_offset:])
                    elif attr_type == '$LOGGED_UTILITY_STREAM':
                        entry_table += tablecreation_instance.logged_utility_stream(hex_dump[current_offset:])

                previous_offset = current_offset
                current_offset = update_offset(hex_dump, current_offset)

            all_tables += entry_table + "\n\n"

        print("Hi")
        return all_tables.rstrip()
    else:
        return 'File not found.'


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
