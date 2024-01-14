'''
Program written by CyberYom
Written in Python 3.11.6

This program is meant to take a MFT file as input, and parse the MFT file, displaying all the information contained
in the MFT file entry such as x-ways templates will.

Program lives on github.
'''
from mfttemplate import tablecreation
from mfttemplate import logic
from prettytable import PrettyTable
from anytree import Node, RenderTree
import os
import sys
import csv
import datetime
import re

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

def handle_path(providedpath, search_name=None, mft_number=None,export_csv=False, extract_ffc=False, view_contents=False,ffs_all_flag=False,shell__flag=False):
    if os.path.exists(providedpath):
        target_bytes = b'\x46\x49\x4C\x45'  # FILE signature
        all_hex_dumps = MFT(providedpath, target_bytes)

        if not all_hex_dumps or all_hex_dumps == ["No MFT entries found."]:
            return "No MFT entries found."
        all_tables = ""
        entry_count = 0 
        all_pretty_tables = []
        tablecreation_instance = tablecreation()
        match_count = 0  # Initialize a counter for matched entries
        entry_count = 0
        fls_dictionary = {}
        startcluster = None

        for hex_dump in all_hex_dumps:
            extracted_name = None
            logic_instance = logic()
            pretty_table = tablecreation_instance.Entry_Header(hex_dump[0:])
            all_pretty_tables.append(pretty_table)
            logical_size = logic_instance.hex_to_uint(''.join(hex_dump[24:28]))
            current_offset = logic_instance.hex_to_short(''.join(hex_dump[20:22]))
            entry_number = logic_instance.hex_to_uint(''.join(hex_dump[44:48]))
            if mft_number is not None:
                entry_number = logic_instance.hex_to_uint(''.join(hex_dump[44:48]))
                if entry_number == mft_number:
                    match_count += 1  # Increment the match count
                else:
                    continue 
            previous_offset = None
            filecontent_data = b''
            filecontent_data = None
            extracted_name = None
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
                        parent_mft_number = logic_instance.bytes_to_decimal(hex_dump[current_offset+24:current_offset+30])
                        attribute_flags = logic_instance.file_attribute_flags(hex_dump[current_offset+80:current_offset+84])
                        namesize_hex = logic_instance.bytes_to_hex(hex_dump[current_offset+88:current_offset+89])
                        namesize = int(namesize_hex, 16) * 2 
                        filename_hex_dump = hex_dump[current_offset+90:current_offset+90+namesize]
                        extracted_name = logic_instance.extract_filename(filename_hex_dump)
                        if parent_mft_number not in fls_dictionary and attribute_flags != 'Hidden':
                            fls_dictionary[parent_mft_number] = []
                        fls_dictionary[parent_mft_number].append((extracted_name, entry_number))
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
                        if da_table:
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
                        all_pretty_tablses.append(rp_table)
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
                    else:
                        pass # Breaks out of the while loop

                previous_offset = current_offset
                current_offset = update_offset(hex_dump, current_offset)

            entry_count += 1 

            if search_name is not None:
                if extracted_name and search_name in extracted_name:
                    match_count += 1  # Increment the match count
                else:
                    continue


            if extracted_name:
                all_tables += f"\033[91m     Entry Header for File: \033[92m{extracted_name}\033[0m - \033[91mEntry Number: \033[92m{entry_number}\033[0m\n"
            else:
                all_tables += "\033[91m     Entry Header for File: Entry without a name\n \033[0m"
                all_tables += f"\033[91m     MFT Entry Number: \033[92m{entry_number}\033[0m\n"



            all_tables += pretty_table.get_string() + "\n\n" 
            all_tables += entry_table  

        if shell__flag is True:
            dump_flag = False
            def find_and_display_file(all_hex_dumps, tablecreation_instance, filename_to_find=None, dump_flag=False):
                file_found = False
                all_pretty_tables = []
                all_tables = ''
                for hex_dump in all_hex_dumps:
                    extracted_name = None
                    pretty_table = tablecreation_instance.Entry_Header(hex_dump[0:])
                    all_pretty_tables.append(pretty_table)
                    logical_size = logic_instance.hex_to_uint(''.join(hex_dump[24:28]))
                    current_offset = logic_instance.hex_to_short(''.join(hex_dump[20:22]))
                    previous_offset = None
                    filecontent_data = None
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
                                if extracted_name and filename_to_find == filename_to_find:
                                    file_found = True
                                
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
                                if da_table:
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
                                all_pretty_tablses.append(rp_table)
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

                            if filename_to_find and extracted_name and filename_to_find in extracted_name:
                                file_found = True  

                            if dump_flag and attr_type == '$DATA':
                                if hex_dump[current_offset+8:current_offset+9] == ['00']:
                                    filecontentlen_hex = logic_instance.bytes_to_hex(hex_dump[current_offset+16:current_offset+20])
                                    filecontentlen = logic_instance.bytes_to_decimal(filecontentlen_hex)
                                    filecontent_hex = hex_dump[current_offset+24:current_offset+24+filecontentlen]
                                    filecontent_data = bytes.fromhex(''.join(filecontent_hex))
                                    break 
                                if hex_dump[current_offset+8:current_offset+9] == ['01']:
                                    startcluster = logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[16:24])))
                                    endcluster = logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[current_offset+24:current_offset+32])))
                                    datarun = logic_instance.hex_to_short(''.join(hex_dump[current_offset+32:current_offset+34]))
                                    Logicalsize = logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[current_offset+40:current_offset+48])))
                                    break
                            else:
                                pass

                        previous_offset = current_offset
                        current_offset = update_offset(hex_dump, current_offset)

                    if filename_to_find and not extracted_name:
                        continue
                
                    if filename_to_find and extracted_name and filename_to_find not in extracted_name:
                        continue

                    all_tables += pretty_table.get_string() + "\n\n" 
                    all_tables += entry_table 

                    if dump_flag == True:
                        data = ""
                        if filecontent_data is not None:
                            output_filename = f'{extracted_name}'
                            try:
                                with open(output_filename, 'wb') as file:
                                    file.write(filecontent_data)

                                stats = os.stat(output_filename)
                                data += f"\033[0m Command: \033[91mdump\033[0m was run on \033[92m{extracted_name}\033[0m\n\n"
                                data += f"Data successfully extracted to '\033[92m{output_filename}\033[0m'.\n"
                                data += f"└────── File Size: {stats.st_size} (Bytes)\n"
                                data += f"└────── File Created At: {datetime.datetime.fromtimestamp(stats.st_atime).strftime('%Y-%m-%d %H:%M:%S')}\n\n"

                                data += f"Content:\n"
                                data += f"───────\n"
                                data += f"{str(filecontent_data)[2:-1]}\n"
                                print(data)
                            except IOError as e:
                                return f"Error writing extracted data to file: {e}"
                        else:
                            pass

                        if startcluster:
                            data +=  "Note that this file is non-resident and thus can not be carved from the MFT.\n\n "
                            data +=  f"Statistics for {extracted_name}\n└────── Starting Cluster: {startcluster}\n└────── Ending Cluster: {endcluster}\n└────── Datarun Offset: {datarun}\n└────── Logical Size of File: {logical_size}"
                            return data
                    else:
                        pass

                if dump_flag == False:
                    print(all_tables.rstrip())

            def build_tree(directory_mft, fls_dictionary, parent_node, visited_mfts):
                # Add the current directory to the visited set
                visited_mfts.add(directory_mft)

                for child_name, child_mft in fls_dictionary.get(directory_mft, []):
                    child_node = Node(child_name, parent=parent_node)
                    # Recur only if the child directory hasn't been visited yet
                    if child_mft in fls_dictionary and child_mft not in visited_mfts:
                        build_tree(child_mft, fls_dictionary, child_node, visited_mfts)


            def print_directory_tree(directory_name, fls_dictionary, indent=""):
                directory_mft_number = None
                for parent_mft, children in fls_dictionary.items():
                    for child_name, child_mft in children:
                        if child_name == directory_name:
                            directory_mft_number = child_mft
                            break
                    if directory_mft_number is not None:
                        break

                if directory_mft_number is None:
                    return f"Directory '{directory_name}' not found."

                for child_name, _ in fls_dictionary.get(directory_mft_number, []):
                    print(f"{indent}{child_name}")
                    if child_name in fls_dictionary:  # Check if the child is a directory
                        print_directory_tree(child_name, fls_dictionary, indent + "    ")

            def list_directory_contents(directory_name, fls_dictionary):
                directory_mft_number = None
                for parent_mft, children in fls_dictionary.items():
                    for child_name, child_mft in children:
                        if child_name == directory_name:
                            directory_mft_number = child_mft
                            break
                    if directory_mft_number is not None:
                        break

                if directory_mft_number is None:
                    return f"Directory '{directory_name}' not found."

                # List the contents of the directory
                directory_contents = []
                for child_name, child_mft in fls_dictionary.get(directory_mft_number, []):
                    directory_contents.append(f"{child_name} (MFT #: {child_mft})")

                return '\n'.join(directory_contents) if directory_contents else "The directory is empty."

            def find_file_path(filename, fls_dictionary):
                def get_parent_path(mft_number, fls_dictionary, path=[]):
                    if mft_number not in fls_dictionary or mft_number == 5:
                        return path
                    for parent_mft, children in fls_dictionary.items():
                        for child_name, child_mft in children:
                            if child_mft == mft_number:
                                # Recursive call
                                return get_parent_path(parent_mft, fls_dictionary, [child_name] + path)
                    return path
                for parent_mft, children in fls_dictionary.items():
                    for child_name, child_mft in children:
                        if filename == child_name:
                            # Construct the path from root to this file
                            path_to_file = get_parent_path(parent_mft, fls_dictionary)
                            return 'C:\\' + '\\'.join(path_to_file[::-1] + [filename])
                return "File not found."

            print('| Version: 0.0.3\n| https://github.com/cyberyom/MFTAnalyzer\n└---------------------------------------------------------------------------')
            print('Welcome to the MFT Shell. Please pass the command \033[92mhelp\033[0m to learn more.\n')

            while True:  # Adding a while loop here
                try:
                    input_command = input("\033[91mMFT Shell\033[0m > ").rstrip()
                    command_parts = input_command.split()
                    if not command_parts:
                        continue
                    command = command_parts[0]  
                    args = command_parts[1:]   

                    if command == 'help':
                        data = '  Available commands:\n'
                        data += '\nhelp\n└────── Display the help menu\n\n'
                        data += 'ls\n└────── View the contents of a Directory\n\n'
                        data += 'cat\n└────── View MFT entry for file\n\n'
                        data += 'find\n└────── Find MFT entry for specific file\n\n'
                        data += 'tree\n└────── Display the file structure of current directory and below\n\n'
                        data += 'tree-all\n└────── Dispay file structure of whole disk\n\n'
                        data += 'dump\n└────── Dump the contents of resident files, for non-resident files, return offsets for carving\n\n'
                        data += 'clear\n└────── Clear the screen'
                        print(data)
                        continue

                    if command == 'tree-all':
                        root = Node("Root")
                        node_references = {0: root}  # Dictionary to keep track of nodes by entry number

                        for key, children in fls_dictionary.items():
                            for child_tuple in children:
                                child_name, entry_number = child_tuple
                                parent_node = node_references.get(key, root)  # Get the parent node, default to root if not found
                                new_node = Node(f"{child_name} (MFT #:{entry_number})", parent=parent_node)
                                node_references[entry_number] = new_node  # Store the new node reference

                        for pre, fill, node in RenderTree(root):
                            print(f"{pre}{node.name}")

                    if command == 'dump':
                        dump_flag = True
                        filename_to_find = args[0]
                        all_hex_dumps = MFT(providedpath, target_bytes)
                        find_and_display_file(all_hex_dumps, tablecreation_instance, filename_to_find, dump_flag)
                        print(find_and_display_file)
                        continue


                    if command == 'cat':
                        if len(args) < 1:
                            print("Please provide a filename.")
                            continue
                        filename_to_find = args[0]
                        all_hex_dumps = MFT(providedpath, target_bytes)
                        find_and_display_file(all_hex_dumps, tablecreation_instance, filename_to_find)
                        continue

                    if command == 'find':
                        if len(args) < 1:
                            print("Please provide a filename to find.")
                            continue
                        find_name = args[0]
                        file_path = find_file_path(find_name, fls_dictionary)
                        print(file_path)
                        continue

                    if command == 'ls':
                        if len(args) < 1:
                            print("Please provide the name of the directory.")
                            continue
                        directory_name = args[0]
                        ls_output = list_directory_contents(directory_name, fls_dictionary)
                        print(ls_output)
                        continue

                    if command == 'tree':
                        if len(args) < 1:
                            print("Please provide the name of the directory.")
                            continue
                        directory_name = args[0]
                        directory_mft_number = None

                        # Find the MFT number for the directory
                        for parent_mft, children in fls_dictionary.items():
                            for child_name, child_mft in children:
                                if child_name == directory_name:
                                    directory_mft_number = child_mft
                                    break
                            if directory_mft_number is not None:
                                break

                        if directory_mft_number is None:
                            print(f"Directory '{directory_name}' not found.")
                        else:
                            root_node = Node(directory_name)
                            build_tree(directory_mft_number, fls_dictionary, root_node, set())  # Include an empty set for visited_mfts
                            for pre, fill, node in RenderTree(root_node):
                                print(f"{pre}{node.name}")

                    if command == 'clear':
                        if os.name == 'nt': 
                            os.system('cls')
                        else:  
                            os.system('clear')
                        continue

                    if command == 'exit':
                        print('\nExiting...')
                        quit()

                except KeyboardInterrupt:
                    quit()
        else:
            pass    

        if not any(arg.startswith('-f') for arg in sys.argv):
            if export_csv:
                export_to_csv(all_pretty_tables, f"{providedpath}_exported.csv")
            
            if search_name or mft_number is not None:
                summary_string = f"\nTotal number of MFT entries processed: {match_count}"
                header = "| Version: 0.0.3\n| https://github.com/cyberyom/MFTAnalyzer\n└----------------------------------------------------------------------------\n"
                return header + all_tables.rstrip() + summary_string
            else:
                summary_string = f"\nTotal number of MFT entries processed: {entry_count}"
                header = "| Version: 0.0.3\n| https://github.com/cyberyom/MFTAnalyzer\n└----------------------------------------------------------------------------\n"
                return header + all_tables.rstrip() + summary_string    
    else:
        return 'File not found.'



def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

def output_results(data, outputpath):
    try:
        with open(outputpath, 'w', encoding='utf-8') as file:
            file.write(strip_ansi_codes(data))
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
""" + "\033[0m" + "      by CyberYom\n")

def firstrun():
    print('Welcome to MFT Analyzer. This tool is designed to parse and display MFT metadata. \nPassing -h will display a help menu.' + '\n\n')

def help():
    print("+------------------------------------+ Help Page +------------------------------------+\n")
    print("Info:\n| This tool is meant to gather and parse data from the NTFS file $MTF. \n| It is intended to display results of all data in table format, \n| offering both readable and raw data.\n")
    print("| To parse an MFT file, simple pass an MFT file to the tool\n└───────./MFTAnalyzer.exe C:\\path\\to\\$MFT\n\n")
    print("Flags:")
    print("| -sn \n└───────./MFTAnalyzer.exe $MFT -sn filename\n\t- Search for a specific file entry based off file name\n")
    print("| -sm \n└───────./MFTAnalyzer.exe $MFT -sm ENTRYNUMBER\n\t- Search for a specific file entry based off MFT file entry number\n")
    print("| -o \n└───────./MFTAnalyzer.exe $MFT -o output.txt\n\t- Output the results to a text file\n")
    print("| --csv \n└───────./MFTAnalyzer.exe $MFT --csv\n\t- Output the results to csv format\n")
    print("| --shell \n└───────./MFTAnalyzer.exe $MFT --shell\n\t- Enter a shell with the MFT file\n\n")
    print("Additional help:\n|Support:\n└───────https://github.com/cyberyom/MFTAnalyzer/issues\n\n")
    print("Version: 0.0.3")
    print("Author: CyberYom")
    print("https://github.com/cyberyom/MFTAnalyzer")





def main():
    search_name = None
    output_path = None
    export_csv = False
    mft_number = None
    extract_ffc = '-ffc' in sys.argv
    ffs_all_flag = False
    view_contents = None
    shell__flag = '--shell' in sys.argv

    if len(sys.argv) == 1:
        firstrun()
        sys.exit(0)

    if '-h' in sys.argv:
        help()
        sys.exit(0)

    if '-fh' in sys.argv:
        fhelp()
        sys.exit(0)
    
    if not any(arg.startswith('-f') for arg in sys.argv):
        if '-sn' in sys.argv:
            try:
                s_index = sys.argv.index('-sn')
                if s_index + 1 < len(sys.argv):
                    search_name = sys.argv[s_index + 1]
                else:
                    print("No search name provided after -s.")
                    sys.exit(1)
            except ValueError:
                print("Error processing -s argument.")
                sys.exit(1)

        if '-sm' in sys.argv:
                try:
                    m_index = sys.argv.index('-sm')
                    if m_index + 1 < len(sys.argv):
                        mft_number = int(sys.argv[m_index + 1])
                    else:
                        print("No MFT number provided after -m.")
                        sys.exit(1)
                except ValueError:
                    print("Error processing -m argument.")
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
 
        if len(sys.argv) > 1:
            argpath = sys.argv[1]
            argpath = os.path.abspath(argpath)
        path_output = handle_path(argpath, search_name, mft_number, export_csv, extract_ffc, view_contents, ffs_all_flag, shell__flag)
        print(path_output)
        if output_path:
            output_results(path_output, output_path)

    elif any(arg.startswith('-f') for arg in sys.argv):
        if '-ffs-all' in sys.argv:
            ffs_all_flag = True

        if '-sn' in sys.argv:
            try:
                s_index = sys.argv.index('-sn')
                if s_index + 1 < len(sys.argv):
                    search_name = sys.argv[s_index + 1]
                else:
                    print("No search name provided after -s.")
                    sys.exit(1)
            except ValueError:
                print("Error processing -s argument.")
                sys.exit(1)

        if '-sm' in sys.argv:
                try:
                    m_index = sys.argv.index('-sm')
                    if m_index + 1 < len(sys.argv):
                        mft_number = int(sys.argv[m_index + 1])
                    else:
                        print("No MFT number provided after -m.")
                        sys.exit(1)
                except ValueError:
                    print("Error processing -m argument.")
                    sys.exit(1)

        if '-fls' in sys.argv:
            view_contents = True
            try:
                fls_index = sys.argv.index('-fls')
                if fls_index + 1 < len(sys.argv):
                    search_name = sys.argv[fls_index + 1]
                else:
                    print("No filename provided after -fls.")
                    sys.exit(1)
            except ValueError:
                print("Error processing -fls argument.")
                sys.exit(1)



        extract_ffc = '-ffc' in sys.argv
        if len(sys.argv) > 1:
            argpath = sys.argv[1]
            argpath = os.path.abspath(argpath)

        extraction_result = handle_path(argpath, search_name, mft_number, export_csv, extract_ffc, view_contents, ffs_all_flag,shell__flag)
        print(extraction_result)

if __name__ == "__main__":
    main() #script execution
