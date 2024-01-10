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
import csv

def MFT(argpath, target_bytes):
    outputs = [] 
    try:
        with open(argpath, 'rb') as file:
            file_content = file.read()
            offset = 0

            while True:
                start_offset = file_content.find(target_bytes, offset)
                if start_offset == -1:
                    break

                logical_size_bytes = file_content[start_offset+24:start_offset+28]
                logical_size = int.from_bytes(logical_size_bytes, byteorder='little')
                entry_end = start_offset + logical_size
                bytes_data = file_content[start_offset:entry_end]
                hex_data = [f'{byte:02x}' for byte in bytes_data]
                outputs.append(hex_data)
                offset = entry_end

        if not outputs:
            return ["No MFT entries found."]

        return outputs  

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
        0x10000000: '$STANDARD_INFORMATION',
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
        return len(hex_dump) 
    logic_instance = logic()
    attr_length_hex = logic_instance.bytes_to_decimal(hex_dump[current_offset+4:current_offset+8])
    return current_offset + attr_length_hex

def handle_path(providedpath, search_name=None, export_csv=False):
    if os.path.exists(providedpath):
        target_bytes = b'\x46\x49\x4C\x45'  # FILE signature
        all_hex_dumps = MFT(providedpath, target_bytes)

        if not all_hex_dumps or all_hex_dumps == ["No MFT entries found."]:
            return "No MFT entries found."

        all_tables = ""
        all_pretty_tables = []
        tablecreation_instance = tablecreation()

        for hex_dump in all_hex_dumps:
            extracted_name = None
            logic_instance = logic()
            pretty_table = tablecreation_instance.Entry_Header(hex_dump[0:])
            all_pretty_tables.append(pretty_table)
            logical_size = logic_instance.hex_to_uint(''.join(hex_dump[24:28]))
            current_offset = logic_instance.hex_to_short(''.join(hex_dump[20:22]))
            previous_offset = None
            entry_table = "" 

            while current_offset < len(hex_dump) and current_offset < logical_size:
                if current_offset == previous_offset:
                    break

                attr_type = determine_attribute_type(hex_dump, current_offset)

                sd_table = None
                si_table = None
                al_table = None
                fn_table = None
                oi_table = None
                vn_table = None
                vii_table = None
                da_table = None
                ir_table = None
                ia_table = None
                bm_table = None
                sl_table = None
                rp_table = None
                eai_table = None
                ea_table = None
                ps_table = None
                lus_table = None

                if attr_type != "Unknown":
                    offset_info = f"    Attribute Type: {attr_type}, Current Offset: {current_offset} \n"
                    entry_table += offset_info
                    if attr_type == '$STANDARD_INFORMATION':
                        si_table = tablecreation_instance.standard_info(hex_dump[current_offset:])
                        all_pretty_tables.append(si_table)
                        entry_table += si_table.get_string() + "\n"


                    elif attr_type == '$ATTRIBUTE_LIST':
                        al_table = tablecreation_instance.attribute_list(hex_dump[current_offset:])
                        all_pretty_tables.append(al_table)
                        entry_table += al_table.get_string() + "\n"


                    if attr_type == '$FILE_NAME':
                        fn_table = tablecreation_instance.file_name(hex_dump[current_offset:])
                        all_pretty_tables.append(fn_table)
                        entry_table += fn_table.get_string() + "\n"
                        namesize_hex = logic_instance.bytes_to_hex(hex_dump[current_offset+88:current_offset+89])
                        namesize = int(namesize_hex, 16) * 2 
                        filename_hex_dump = hex_dump[current_offset+90:current_offset+90+namesize]
                        extracted_name = logic_instance.extract_filename(filename_hex_dump)

                    elif attr_type == '$OBJECT_ID':
                        oi_table = tablecreation_instance.object_id(hex_dump[current_offset:])
                        if oi_table is not None:
                            all_pretty_tables.append(oi_table)
                            entry_table += oi_table.get_string() + "\n"

                    elif attr_type == '$SECURITY_DESCRIPTOR':
                        sd_table = tablecreation_instance.security_descriptor(hex_dump[current_offset:])
                        if sd_table is not None:
                            all_pretty_tables.append(sd_table)
                            entry_table += sd_table.get_string() + "\n"

                    elif attr_type == "$VOLUME_NAME":
                        vn_table = tablecreation_instance.volume_name(hex_dump[current_offset:])
                        if vn_table is not None:
                            all_pretty_tables.append(vn_table)
                            entry_table += vn_table.get_string() + "\n"

                    elif attr_type == '$VOLUME_INFORMATION':
                        vii_table = tablecreation_instance.volume_information(hex_dump[current_offset:])
                        all_pretty_tables.append(vii_table)
                        entry_table += vii_table.get_string() + "\n"

                    elif attr_type == '$DATA':
                        da_table = tablecreation_instance.data(hex_dump[current_offset:])
                        all_pretty_tables.append(da_table)
                        entry_table += da_table.get_string() + "\n"

                    elif attr_type == '$INDEX_ROOT':
                        ir_table = tablecreation_instance.index_root(hex_dump[current_offset:])
                        all_pretty_tables.append(ir_table)
                        entry_table += ir_table.get_string() + "\n"

                    elif attr_type == '$INDEX_ALLOCATION':
                        ia_table = tablecreation_instance.index_allocation(hex_dump[current_offset:])
                        all_pretty_tables.append(ia_table)
                        entry_table += ia_table.get_string() + "\n"

                    elif attr_type == '$BITMAP':
                        bm_table = tablecreation_instance.bitmap(hex_dump[current_offset:])
                        all_pretty_tables.append(bm_table)
                        entry_table += bm_table.get_string() + "\n"

                    elif attr_type == '$SYMBOLIC_LINK':
                        sl_table = tablecreation_instance.index_root(hex_dump[current_offset:])
                        all_pretty_tables.append(sl_table)
                        entry_table += sl_table.get_string() + "\n"

                    elif attr_type == '$REPARSE_POINT':
                        rp_table = tablecreation_instance.reparse_point(hex_dump[current_offset:])
                        all_pretty_tables.append(rp_table)
                        entry_table += rp_table.get_string() + "\n"

                    elif attr_type == '$EA_INFORMATION':
                        eai_table = tablecreation_instance.ea_information(hex_dump[current_offset:])
                        all_pretty_tables.append(eai_table)
                        entry_table += eai_table.get_string() + "\n"

                    elif attr_type == '$EA':
                        ea_table = tablecreation_instance.ea(hex_dump[current_offset:])
                        all_pretty_tables.append(ea_table)
                        entry_table += ea_table.get_string() + "\n"

                    elif attr_type == 'PROPERTY_SET':
                        ps_table = tablecreation_instance.property_set(hex_dump[current_offset:])
                        all_pretty_tables.append(ps_table)
                        entry_table += ps_table.get_string() + "\n"

                    elif attr_type == '$LOGGED_UTILITY_STREAM':
                        lus_table = tablecreation_instance.logged_utility_stream(hex_dump[current_offset:])
                        all_pretty_tables.append(lus_table)
                        entry_table += lus_table.get_string() + "\n"

                previous_offset = current_offset
                current_offset = update_offset(hex_dump, current_offset)

            if search_name and not extracted_name:
                continue
            
            if search_name and extracted_name and search_name not in extracted_name:
                continue

            if extracted_name:
               all_tables += f"\033[91m     Entry Header for File: \033[92m{extracted_name}\033[0m\n"

            else:
                all_tables += "\033[91m     Entry Header for File: Entry without a name\n \033[0m"

            all_tables += pretty_table.get_string() + "\n\n" 
            all_tables += entry_table  

        if export_csv:
            export_to_csv(all_pretty_tables, f"{providedpath}_exported.csv")

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


def export_to_csv(tables, filename):
    with open(filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        for table in tables:
            csvwriter.writerow(table.field_names)
            for row in table._rows:
                csvwriter.writerow(row)




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
    print("+------------------------------------+ Help Page +------------------------------------+\n")
    print("This tool has a few options available. \n")
    print("For simply parsing an MFT file, pass the location of the MFT file.\n-----./MFTAnalyzer.exe C:\\Path\\To\\MFTfile-----\n")
    print("To search for specific file entries, pass the -s flag, along with the string to search for.\n-----./MFTAnalyzer.exe C:\\Path\\To\\MFT -s testfile -----\n")
    print("To export your results, use the -o flag.\n-----./MFTAnalyzer.exe C:\\Path\\To\\MFTfile -o C:\\Desired\\Path\\To\\Results.txt-----\n")
    print("To export your results to a CSV, pass the --csv flag.\n-----./MFTAnalyzer.exe C:\\Path\\To\\MFT --csv -----\n")
    print("To view the forensic module help page, pass the -fh flag.\n-----./MFTAnalyzer.exe -fh -----\n")
    print("+-------------------------------------------------------------------------------------+\n")

def fhelp():
    print("+----------------------------+ Forensic Module Help Page +----------------------------+\n")
    print("Info:\n| All forensic modules offer a number of differnt helpful forensic \n| informational tools that is gathered and processed from the MFT file.\n\n\n")
    print("Flags:\n")
    print("| -fo                      \n\t-./MFTAnalyzer.exe $MFT -s file.txt -fo \n\t- Pass the offset of a specific file\n")
    print("| -ffs-flag                \n\t-. /MFTAnalyzer.exe $MFT -s file.txt --ffs-flag/MFTAnalyzer.exe $MFT -s file.txt --ffs-flag \n\t- Pass to list file structure from a file\n")
    print("| -fls                     \n\t-./MFTAnalyzer.exe $MFT -s directory -fls \n\t- Pass to list contents of a folder\n")
    print("Additional help:\n|Contact:\n\t-https://github.com/cyberyom/MFTAnalyzer/tree/forensic-modules\n")
    print("Feel free to visit the project.")



def main():
    search_name = None
    search_flag = False
    output_path = None
    export_csv = False

    if len(sys.argv) == 1:
        firstrun()
        sys.exit(0)

    if '-h' in sys.argv:
        help()
        sys.exit(0)

    if '-fh' in sys.argv:
        fhelp()
        sys.exit(0)

    if '-s' in sys.argv:
        try:
            s_index = sys.argv.index('-s')
            if s_index + 1 < len(sys.argv):
                search_name = sys.argv[s_index + 1]
                search_flag = True
            else:
                print("No search name provided after -s.")
                sys.exit(1)
        except ValueError:
            print("Error processing -s argument.")
            sys.exit(1)

    if '-o' in sys.argv:
        try:
            o_index = sys.argv.index('-o')
            if o_index + 1 < len(sys.argv):
                output_path = sys.argv[o_index + 1]
            else:
                
                print("No output path provided after -o.")
                sys.exit(1)
        except ValueError:
            print("Error processing -o argument.")
            sys.exit(1)

    if '--csv' in sys.argv:
        export_csv = True

    argpath = sys.argv[1]
    path_output = handle_path(argpath, search_name if search_flag else None, export_csv)
    print(path_output)
    if output_path:
        output_results(path_output, output_path)

if __name__ == "__main__":
    main() #script execution
