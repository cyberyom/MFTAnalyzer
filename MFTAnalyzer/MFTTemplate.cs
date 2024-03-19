// This file is simply used to parse the MFT file. All that is here are functions to parse MFT raw data and functions to create tables

using System;
using System.Diagnostics.Tracing;
using System.Security.Cryptography;
using System.Text;
using ConsoleTables;

namespace MFTAnalyzer
{
    public class tableLogic
    {
        static Dictionary<ushort, string> entryFlagsDictionary = new Dictionary<ushort, string>
            {
                { 0x0001, "File In Use" },
                { 0x0002, "Suspected Directory" },
                { 0x0004, "Present in $Extend" },
                { 0x0008, "Index File" }
            };

        public static string FileAttributeFlags(byte[] hexDump)
        {
            if (hexDump.Length != 4)
            {
                return "Invalid input length for file attribute flags";
            }

            // Convert byte array to integer
            uint attributeFlagInt = BitConverter.ToUInt32(hexDump, 0);

            Dictionary<uint, string> attributeFlags = new Dictionary<uint, string>
            {
                { 0x00000001, "Read-only" },
                { 0x00000002, "Hidden" },
                { 0x00000004, "System" },
                { 0x00000020, "Archive" },
                { 0x00000040, "Device" },
                { 0x00000080, "Normal" },
                { 0x00000100, "Temporary" },
                { 0x00000200, "Sparse file" },
                { 0x00000400, "Reparse point" },
                { 0x00000800, "Compressed" },
                { 0x00001000, "Offline" },
                { 0x00002000, "Not content indexed" },
                { 0x00004000, "Encrypted" },
                { 0x00008000, "Integrity stream" },
                { 0x01000000, "Virtual" },
                { 0x02000000, "No scrub data" },
                { 0x10000000, "Suspected Directory" }
            };

            List<string> matchedAttributes = new List<string>();

            foreach (var flag in attributeFlags)
            {
                if ((attributeFlagInt & flag.Key) == flag.Key)
                {
                    matchedAttributes.Add(flag.Value);
                }
            }

            return matchedAttributes.Count > 0 ? string.Join(", ", matchedAttributes) : "No matching attributes or Unknown Attribute Flag";
        }

        public static string attrData(byte attrDataTypes)
        {
            switch (attrDataTypes)
            {
                case 0x01: return "Is Compressed"; break;
                case 0xff: return "-"; break;
                case 0x40: return "Is Encrypted"; break;
                case 0x80: return "Is Sparse"; break;
                default: return "-"; break;
            }
        }
        public static string residency(byte residencyFlag)
        {
            if (residencyFlag == 0x01) { return "Non Resident"; }
            else if (residencyFlag == 0x00) { return "Resident"; }
            return "Unknown";
        }
        public static string EntryHeaderFlags(byte[] flags)
        {
            ushort flagValue = BitConverter.ToUInt16(flags, 0);
            string flagDescriptions = "";
            bool knownFlagFound = false;
            foreach (var flag in entryFlagsDictionary)
            {
                if ((flagValue & flag.Key) == flag.Key)
                {
                    if (!string.IsNullOrEmpty(flagDescriptions))
                        flagDescriptions += ", ";
                    flagDescriptions += flag.Value;
                    knownFlagFound = true;
                }
            }
            if (!knownFlagFound)
            {
                if (!string.IsNullOrEmpty(flagDescriptions))
                    flagDescriptions += ", ";
                flagDescriptions += "-";
            }
            return flagDescriptions;
        }
        public static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";
        }

    }

    public class tableCreation
    {
        public string entryHeader(byte[] mftEntry)
        {
            string flagsDescription = tableLogic.EntryHeaderFlags(mftEntry.Skip(22).Take(2).ToArray());
            var table = new ConsoleTable("Title", "Raw Data", "Data");
            table.AddRow("Signature", BitConverter.ToString(mftEntry, 0, 4).Replace("-", " "), Encoding.ASCII.GetString(mftEntry, 0, 4)); //ascii
            table.AddRow("Update Sequence Offset", BitConverter.ToString(mftEntry, 4, 2).Replace("-", " "), BitConverter.ToInt16(mftEntry, 4)); //short
            table.AddRow("Update Sequence Size", BitConverter.ToString(mftEntry, 6, 2).Replace("-", " "), BitConverter.ToInt16(mftEntry, 6)); 
            table.AddRow("Logfile Sequence Number", BitConverter.ToString(mftEntry, 8, 8).Replace("-", " "), BitConverter.ToUInt64(mftEntry, 8)); //unit64
            table.AddRow("Use/Deletion Count", BitConverter.ToString(mftEntry, 16, 2).Replace("-", " "), BitConverter.ToInt16(mftEntry, 16));
            table.AddRow("Hard-link Count", BitConverter.ToString(mftEntry, 18, 2).Replace("-", " "), BitConverter.ToInt16(mftEntry, 18));
            table.AddRow("Offset to First Attr", BitConverter.ToString(mftEntry, 20, 2).Replace("-", " "), BitConverter.ToInt16(mftEntry, 20));
            table.AddRow("Flags", BitConverter.ToString(mftEntry, 22, 2).Replace("-", " "), flagsDescription);
            table.AddRow("Logical Size of Record", BitConverter.ToString(mftEntry, 24, 4).Replace("-", " "), BitConverter.ToUInt32(mftEntry, 24)); //un
            table.AddRow("Physical Size of Record", BitConverter.ToString(mftEntry, 28, 4).Replace("-", " "), BitConverter.ToUInt32(mftEntry, 28));
            table.AddRow("Base Record", BitConverter.ToString(mftEntry, 32, 8).Replace("-", " "), BitConverter.ToUInt64(mftEntry, 32));
            table.AddRow("MFT Entry Number", BitConverter.ToString(mftEntry, 44, 4).Replace("-", " "), BitConverter.ToUInt32(mftEntry, 44));
                        
            return table.ToMinimalString();
        }

        private ConsoleTable table; //creates table for attrheader and attr
        public void attrHeader(byte[] mftEntry, int currentOffset, string attrType)
        {
            int maxLength = Math.Max(10, Console.WindowWidth / 4);
            this.table = new ConsoleTable("Title", "Raw Data", "Data");
            byte residencyFlag = mftEntry[currentOffset + 8];
            byte attrDataFlags = mftEntry[currentOffset + 12];
            this.table.AddRow("Attribute Type", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset, 4).Replace("-", " "), maxLength), attrType);
            this.table.AddRow("Attribute Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 4, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 4));
            this.table.AddRow("Attribute Residency", tableLogic.Truncate(BitConverter.ToString(new byte[] { residencyFlag }, 0, 1).Replace("-", " "), maxLength), tableLogic.residency(residencyFlag)); // Corrected call            this.table.AddRow("Name Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 9, 1).Replace("-", " "), maxLength), BitConverter.ToString(mftEntry, currentOffset + 9, 1).Replace("-", " "));
            this.table.AddRow("Name Offset", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 10, 2).Replace("-", " "), maxLength), BitConverter.ToInt16(mftEntry, currentOffset + 10));
            this.table.AddRow("Attr. Data Flags", tableLogic.Truncate(BitConverter.ToString(new byte[] { attrDataFlags }, 0, 1).Replace("-", " "), maxLength), tableLogic.attrData(attrDataFlags)); //needs function
            this.table.AddRow("Attr. ID", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 14, 2).Replace("-", " "), maxLength), BitConverter.ToInt16(mftEntry, currentOffset + 14));
        }

        public string standardInfo(byte[] mftEntry, int currentOffset)
        {
            int maxLength = Math.Max(10, Console.WindowWidth / 4);
            this.table.AddRow("File Creation", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 24, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 24)));
            this.table.AddRow("File Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 32, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 32)));
            this.table.AddRow("MFT Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 40, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 40)));
            this.table.AddRow("File Accessed", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 48, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 48)));

            // Extract the 4 bytes representing the attribute flags
            byte[] attributeFlagsBytes = new byte[4];
            Array.Copy(mftEntry, currentOffset + 56, attributeFlagsBytes, 0, 4);
            // Call FileAttributeFlags to get the flags' descriptions
            string attributeFlagsDescription = tableLogic.FileAttributeFlags(attributeFlagsBytes);

            this.table.AddRow("Attribute Flags", tableLogic.Truncate(BitConverter.ToString(attributeFlagsBytes).Replace("-", " "), maxLength), attributeFlagsDescription); // Now calling FileAttributeFlags
            this.table.AddRow("Max Versions", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 60, 4).Replace("-", " "), maxLength), "-");
            this.table.AddRow("Version Number", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 64, 4).Replace("-", " "), maxLength), "-");
            this.table.AddRow("Class Identifier", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 68, 4).Replace("-", " "), maxLength), "-");
            this.table.AddRow("Owner Identifier", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 72, 4).Replace("-", " "), maxLength), "-");
            this.table.AddRow("Security Identifier", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 76, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 76));
            this.table.AddRow("Quota Changed", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 80, 8).Replace("-", " "), maxLength), "-");
            this.table.AddRow("Update Sequence Number", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 88, 8).Replace("-", " "), maxLength), "-");
            return this.table.ToMinimalString();
        }

        public string attrList(byte[] mftEntry, int currentOffset)
        {
            return this.table.ToMinimalString(); //unknown
        }

        public string fileName(byte[] mftEntry, int currentOffset)
        {
            int maxLength = Math.Max(10, Console.WindowWidth / 4);
            int nameSize = mftEntry[currentOffset + 88];
            string fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2);
            this.table.AddRow("Parent MFT Reference", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 24, 6).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 24));
            this.table.AddRow("File Creation", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 32, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 32)));
            this.table.AddRow("File Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 40, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 40)));
            this.table.AddRow("MFT Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 48, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 48)));
            this.table.AddRow("File Accessed", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 56, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 56)));
            this.table.AddRow("Logical File Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 64, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 64));
            this.table.AddRow("Physical File Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 72, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 72));

            // Extract the 4 bytes representing the attribute flags for the file name
            byte[] attributeFlagsBytes = new byte[4];
            Array.Copy(mftEntry, currentOffset + 80, attributeFlagsBytes, 0, 4);
            // Call FileAttributeFlags to get the flags' descriptions
            string attributeFlagsDescription = tableLogic.FileAttributeFlags(attributeFlagsBytes);
            this.table.AddRow("Attribute Flags", tableLogic.Truncate(BitConverter.ToString(attributeFlagsBytes).Replace("-", " "), maxLength), attributeFlagsDescription);

            this.table.AddRow("Extended Attribute Data", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 84, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 84));
            this.table.AddRow("Name Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 88, 1).Replace("-", " "), maxLength), nameSize.ToString());
            this.table.AddRow("File Name", tableLogic.Truncate(fileName, maxLength), fileName); // Corrected to directly use `fileName` instead of converting bytes again
            return this.table.ToMinimalString();
        }


        public string objectID(byte[] mftEntry, int currentOffset)
        {
            return this.table.ToMinimalString();
        }

        public string securityDescriptor(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string volumeName(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string volumeInformation(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string data(byte[] mftEntry, int currentOffset) 
        {
            if (mftEntry[currentOffset + 8] == 0x00)
            {
                int maxLength = Math.Max(10, Console.WindowWidth / 4);
                int fileLength = BitConverter.ToInt32(mftEntry, currentOffset + 16);
                this.table.AddRow("File Content Length", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 16, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 16));
                this.table.AddRow("Offset to Content", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 20, 2).Replace("-", " "), maxLength), BitConverter.ToInt16(mftEntry, currentOffset + 20));
                this.table.AddRow("File Content", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 22, fileLength).Replace("-", " "), maxLength), tableLogic.Truncate(Encoding.ASCII.GetString(mftEntry, currentOffset + 22, fileLength), maxLength));
                return table.ToMinimalString();
            }
            else
            {
                int maxLength = Math.Max(10, Console.WindowWidth / 4);
                this.table.AddRow("Starting Cluster Number", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 16, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 16));
                this.table.AddRow("Ending Cluster Number", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 24, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset  + 24));
                this.table.AddRow("Datarun Offset", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 32, 2).Replace("-", " "), maxLength), BitConverter.ToInt16(mftEntry, currentOffset + 32 ));
                this.table.AddRow("Logical File Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 40, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 40));
                this.table.AddRow("Physical File Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 48, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 48));
                this.table.AddRow("Initialized Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 56, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 56));
                int datarunOffset = BitConverter.ToInt16(mftEntry, currentOffset + 32);
                this.table.AddRow("Datarun Offset", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 32, 2).Replace("-", " "), maxLength), datarunOffset);
                this.table.AddRow("Data Run Header", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 64, 1).Replace("-", ""), maxLength), mftEntry[currentOffset + 64].ToString());
                this.table.AddRow("File Length", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 65, 1).Replace("-", ""), maxLength), mftEntry[currentOffset + 65].ToString());
                byte[] clusterOffsetBytes = new byte[] { mftEntry[currentOffset + 66], mftEntry[currentOffset + 67], mftEntry[currentOffset + 68] };
                byte[] paddedBytes = new byte[] { clusterOffsetBytes[0], clusterOffsetBytes[1], clusterOffsetBytes[2], 0 };
                int clusterOffset = BitConverter.ToInt32(paddedBytes, 0);
                this.table.AddRow("Cluster Offset", tableLogic.Truncate(BitConverter.ToString(clusterOffsetBytes).Replace("-", " "), maxLength), clusterOffset.ToString());
                if (mftEntry[currentOffset + 64 + 5] != 0 || mftEntry[currentOffset + 64 + 6] != 0 || mftEntry[currentOffset + 64 + 7] != 0)
                {
                    this.table.AddRow("Data Run Header", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 64 + 5, 1).Replace("-", " "), maxLength), BitConverter.ToString(mftEntry, currentOffset + 64 + 5, 1));
                    this.table.AddRow("File Length", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 65 + 5, 1).Replace("-", " "), maxLength), BitConverter.ToString(mftEntry, currentOffset + 65 + 5, 1));
                    this.table.AddRow("Cluster Offset", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 66 + 5, 3).Replace("-", " "), maxLength), BitConverter.ToString(mftEntry, currentOffset + 66 + 5, 3));
                }
            }

            return table.ToMinimalString();
        }
        public string indexRoot(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string indexAllocation(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string bitmap(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string reparsePoint(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string eaInformation(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        } 

        public string ea(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string propertySet(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }

        public string loggedUtilityStream(byte[] mftEntry, int currentOffset)
        {
            return table.ToMinimalString();
        }
    }
}
