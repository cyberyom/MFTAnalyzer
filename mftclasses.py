'''
This file contains all of the functions used for table creation
as well as the logic behind the raw data conversion to readable data
'''
from datetime import datetime, timedelta
import struct
from prettytable import PrettyTable


class logic:
    def __init__(self):
        pass

    def convert_hex_timestamp_to_datetime(self, hex_timestamp):
        try:
            decimal_timestamp = int(hex_timestamp, 16)
            if decimal_timestamp > 0xFFFFFFFFFFFFFFFF:
                return "Invalid Timestamp"

            windows_epoch_start = datetime(1601, 1, 1)
            microseconds = decimal_timestamp // 10
            converted_datetime = windows_epoch_start + timedelta(microseconds=microseconds)
            return converted_datetime
        except (ValueError, OverflowError):
            return "Invalid Timestamp"

    def timestamp_from_hex_dump(self, hex_dump):
        hex_timestamp = ''.join(hex_dump)
        datetime_obj = self.convert_hex_timestamp_to_datetime(hex_timestamp)

        if isinstance(datetime_obj, str):
            return datetime_obj
        else:
            return datetime_obj.strftime('%Y-%m-%d %H:%M:%S')

    def extract_filename(self, hex_dump):
        name_hex = []

        for i in range(0, len(hex_dump), 2):
            if hex_dump[i] != '00':
                name_hex.append(hex_dump[i])

        return self.hex_to_ascii(name_hex)

    def hex_to_ascii(self, hex_bytes):
        ascii_str = ''

        for hex_byte in hex_bytes:
            byte_int = int(hex_byte, 16)

            if byte_int == 0:
                ascii_str += ''

            else:
                ascii_str += chr(byte_int) if 32 <= byte_int < 127 else '.'

        return ascii_str

    def hex_to_short(self, hex_str):
        try:
            reversed_hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))

            decimal_value = int(reversed_hex_str, 16)

            if decimal_value > 32767 or decimal_value < -32768:
                return "Out of range for short"

            return decimal_value

        except (ValueError, OverflowError):
            return "Invalid Hex Value"

    def filetime_to_dt(self, filetime_bytes):
        filetime_int = struct.unpack('<Q', filetime_bytes)[0]
        windows_epoch = datetime(1601, 1, 1)
        return windows_epoch + timedelta(microseconds=filetime_int // 10)

    def bytes_to_uint32(self, hex_str):
        if not isinstance(hex_str, str):
            raise TypeError("Expected hex_str to be a string")

        byte_data = bytes.fromhex(hex_str)
        return int.from_bytes(byte_data, byteorder='little')



    def bytes_to_hex(self,byte_data):
        hex_string = ''.join(format(int(byte, 16), '02X') for byte in byte_data)
        return hex_string


    def hex_to_uint(self, hex_str):
        try:
            reversed_hex_str = ''.join(reversed([hex_str[i:i+2] for i in range(0, len(hex_str), 2)]))
            
            decimal_value = int(reversed_hex_str, 16)

            if decimal_value < 0:
                return "Negative value not allowed for uint"

            return decimal_value

        except (ValueError, OverflowError):
            return "Invalid Hex Value"

    def bytes_to_uint64(self, raw_bytes):
        if len(raw_bytes) != 8:
            raise ValueError("Input must be exactly 8 bytes long")
        uint64_value = struct.unpack('Q', raw_bytes)[0]
        return uint64_value

    def bytes_to_decimal(self, hex_string_list):
        byte_data = bytes.fromhex(''.join(hex_string_list))
        return int.from_bytes(byte_data, byteorder='little')

    def residency(self, hex_dump):
        if len(hex_dump) != 1:
            return "Invalid input length"
        if hex_dump[0] == '00':
            return "Resident"
        elif hex_dump[0] == '01':
            return "Nonresident"
        else:
            return "Invalid residency byte"

    def dataflag(self, hex_dump):
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
            return "-"

    def file_attribute_flags(self, hex_dump):
        if len(hex_dump) != 4:
            return "Invalid input length for file attribute flags"

        reversed_hex_dump = hex_dump[::-1]
        flag_hex = ''.join(reversed_hex_dump)
        attribute_flags = {
            0x01000000: "Read-only",
            0x02000000: "Hidden",
            0x04000000: "System",
            0x20000000: "Archive",
            0x40000000: "Device",
            0x80000000: "Normal",
            0x00010000: "Temporary",
            0x00020000: "Sparse file",
            0x00040000: "Reparse point",
            0x00080000: "Compressed",
            0x00100000: "Offline",
            0x00200000: "Not content indexed",
            0x00400000: "Encrypted",
            0x00800000: "Integrity stream",
            0x00000100: "Virtual",
            0x00000200: "No scrub data",
        }

        return attribute_flags.get(flag_hex, "Unknown Attribute Flag")


class tablecreation:
    def __init__(self):
        pass
        
    def Entry_Header(hex_dump):
        logic_instance = logic() 
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Signature", ' '.join(hex_dump[:4]), logic_instance.hex_to_ascii(hex_dump[:4])])  # Use the first 4 bytes for Signature
        table.add_row(["Update Sequence Offset", ' '.join(hex_dump[4:6]), logic_instance.hex_to_short(''.join(hex_dump[4:6]))])
        table.add_row(["Update Sequence Size", ' '.join(hex_dump[6:8]), logic_instance.hex_to_short(''.join(hex_dump[6:8]))])
        table.add_row(["Logfile Sequence Number", ' '.join(hex_dump[8:16]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[8:16])))])
        table.add_row(["Use/Deletion Count", ' '.join(hex_dump[16:18]), logic_instance.hex_to_short(''.join(hex_dump[16:18]))])
        table.add_row(["Hard-link Count", ' '.join(hex_dump[18:20]), logic_instance.hex_to_short(''.join(hex_dump[18:20]))])
        table.add_row(["Offset to First Attribute", ' '.join(hex_dump[20:22]), logic_instance.hex_to_short(''.join(hex_dump[20:22]))])
        table.add_row(["Flags", ' '.join(hex_dump[22:24]), logic_instance.hex_to_ascii(hex_dump[22:24])])
        table.add_row(["Logical Size of Record", ' '.join(hex_dump[24:28]), logic_instance.hex_to_uint(''.join(hex_dump[24:28]))])
        table.add_row(["Physical Size of Record", ' '.join(hex_dump[28:32]), logic_instance.hex_to_uint(''.join(hex_dump[28:32]))])
        table.add_row(["Base Record", ' '.join(hex_dump[32:40]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[32:40])))])
        
        return table.get_string() + "\n\n"

    def standard_info(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Standard Information"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])
        table.add_row(["File Creation", ' '.join(hex_dump[24:32]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[24:32]]))])
        table.add_row(["File Modification", ' '.join(hex_dump[32:40]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[32:40]]))])
        table.add_row(["MFT Modification", ' '.join(hex_dump[40:48]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[40:48]]))])
        table.add_row(["File Accessed", ' '.join(hex_dump[48:56]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[48:56]]))])
        table.add_row(["Attribute Flags", ' '.join(hex_dump[56:60]), logic_instance.bytes_to_hex(hex_dump[56:60])])
        table.add_row(["Max Versions", ' '.join(hex_dump[60:64]), "Unknown"])
        table.add_row(["Version Number", ' '.join(hex_dump[64:68]), "Unknown"])
        table.add_row(["Class Identifier", ' '.join(hex_dump[68:72]), "Unknown"])
        table.add_row(["Owner Identifier", ' '.join(hex_dump[72:76]), "Unknown"])
        table.add_row(["Security Identifier", ' '.join(hex_dump[76:80]), logic_instance.bytes_to_decimal(hex_dump[76:80])])
        table.add_row(["Quota Charged", ' '.join(hex_dump[80:88]), "Unknown"])
        table.add_row(["Update Sequence Number", ' '.join(hex_dump[88:96]), "Unknown"])

        return table.get_string() + "\n"


    def attribute_list(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Attribute List"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"


    def file_name(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$File Name"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])
        table.add_row(["Parent MFT Reference", ' '.join(hex_dump[24:32]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[24:32])))])
        table.add_row(["File Creation",' '.join(hex_dump[32:40]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[32:40]]))])
        table.add_row(["File Modification",' '.join(hex_dump[40:48]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[40:48]]))])
        table.add_row(["MFT Modification",' '.join(hex_dump[48:56]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[48:56]]))])
        table.add_row(["File Accessed",' '.join(hex_dump[56:64]), logic_instance.filetime_to_dt(bytes([int(b, 16) for b in hex_dump[56:64]]))])
        table.add_row(["Logical File Size", ' '.join(hex_dump[64:72]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[64:72])))])
        table.add_row(["Physical File Size", ' '.join(hex_dump[72:80]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[72:80])))])
        table.add_row(["Attribute Flags", ' '.join(hex_dump[80:84]), logic_instance.file_attribute_flags(hex_dump[80:84])])
        table.add_row(["Extended Attribute Data", ' '.join(hex_dump[84:88]), logic_instance.bytes_to_decimal(hex_dump[84:88])])
        namesize_hex = logic_instance.bytes_to_hex(hex_dump[88:89])
        namesize = int(namesize_hex, 16) * 2  # Multiply by 2 as each character is represented by 2 bytes
        filename_hex_dump = hex_dump[90:90+namesize]
        extracted_name = logic_instance.extract_filename(filename_hex_dump)
        table.add_row(["File Name", ' '.join(filename_hex_dump), extracted_name]) 

        return table.get_string() + "\n"

  
    def volume_version(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Volume Version"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])
        return table.get_string() + "\n"

    
    def object_id(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Object ID"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])
        return table.get_string() + "\n"

    def security_descriptor(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Attribute List"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def volume_name(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Volume Name"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def volume_information(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Volume Information"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

   
    def volume_information(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Volume Information"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"


    def data(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[0:4]), "$Data"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        if logic_instance.residency(hex_dump[8:9]) == "Nonresident":
            table.add_row(["Starting Cluster Number", ' '.join(hex_dump[16:24]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[16:24])))])
            table.add_row(["Ending Cluster Number", ' '.join(hex_dump[24:32]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[24:32])))])
            table.add_row(["Datarun Offset", ' '.join(hex_dump[32:34]), logic_instance.hex_to_short(''.join(hex_dump[32:34]))])
            table.add_row(["Logical File Size", ' '.join(hex_dump[40:48]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[40:48])))])
            table.add_row(["Physical File Size", ' '.join(hex_dump[48:56]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[48:56])))])
            table.add_row(["Initialized Size", ' '.join(hex_dump[56:64]), logic_instance.bytes_to_uint64(bytes.fromhex(''.join(hex_dump[56:64])))])
       
        elif logic_instance.residency(hex_dump[8:9]) == "Resident":
            filecontent_hex = logic_instance.bytes_to_hex(hex_dump[16:20])
            filecontent = int(filecontent_hex, 16)
            table.add_row(["File Content Length", ' '.join(hex_dump[16:20]), filecontent_hex])
            table.add_row(["Offsent to Content", ' '.join(hex_dump[20:22]), logic_instance.hex_to_short(''.join(hex_dump[20:22]))])
            table.add_row(["File Content", ' '.join(hex_dump[24:24+filecontent]), logic_instance.hex_to_ascii(hex_dump[24:24+filecontent])])

        return table.get_string() + "\n"


    def index_root(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Index Root"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def index_allocation(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Index Allocation"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def bitmap(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Bitmap"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def reparse_point(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Reparse Point"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def ea_information(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$EA Information"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def ea(self, hex_dump):
        logic_instance = logic()
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$EA"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def property_set(self, hex_dump):
        logic_instance = logic() 
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Property Set"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"

    def logged_utility_stream(self, hex_dump):
        logic_instance = logic()  
        table = PrettyTable()
        table.field_names = ["Title", "Raw Data", "Data"]
        table.max_width["Title"] = 30
        table.max_width["Raw Data"] = 60
        table.max_width["Data"] = 30
        table.add_row(["Attribute Type", ' '.join(hex_dump[:4]), "$Logged Utility Stream"])
        table.add_row(["Attribute Size", ' '.join(hex_dump[4:8]), logic_instance.bytes_to_hex(hex_dump[4:8])])
        table.add_row(["Attribute logic.residency", ' '.join(hex_dump[8:9]), logic_instance.residency(hex_dump[8:9])])
        table.add_row(["Name Size", ' '.join(hex_dump[9:10]), hex_dump[9:10]])
        table.add_row(["Name Offset", ' '.join(hex_dump[10:12]), logic_instance.hex_to_short(''.join(hex_dump[10:12]))])
        table.add_row(["Attr. Data Flags", ' '.join(hex_dump[12:14]), logic_instance.dataflag(hex_dump[12:14])])
        table.add_row(["Attr. ID", ' '.join(hex_dump[14:16]), logic_instance.hex_to_short(''.join(hex_dump[14:16]))])

        return table.get_string() + "\n"
