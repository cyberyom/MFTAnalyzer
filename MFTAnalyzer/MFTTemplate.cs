using System;
using System.Security.Cryptography;
using System.Text;
using ConsoleTables;

namespace MFTAnalyzer
{
    public class tableLogic
    {
        public static string EntryHeaderFlags(byte[] flags)
        {
            var flagsDictionary = new Dictionary<ushort, string>
            {
                { 0x0001, "File In Use" },
                { 0x0002, "Suspected Directory" },
                { 0x0004, "Present in $Extend" },
                { 0x0008, "Index File" }
            };

            ushort flagValue = BitConverter.ToUInt16(flags, 0);
            string flagDescriptions = "";
            bool knownFlagFound = false;

            foreach (var flag in flagsDictionary)
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
                flagDescriptions += "Unknown";
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
            this.table.AddRow("Attribute Type", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset, 4).Replace("-", " "), maxLength), attrType);
            this.table.AddRow("Attribute Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 4, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 4));
            this.table.AddRow("Attribute Residency", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 8, 1).Replace("-", " "), maxLength), "data"); //needs function
            this.table.AddRow("Name Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 9, 1).Replace("-", " "), maxLength), BitConverter.ToString(mftEntry, currentOffset + 9, 1).Replace("-", " "));
            this.table.AddRow("Name Offset", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 10, 2).Replace("-", " "), maxLength), BitConverter.ToInt16(mftEntry, currentOffset + 10));
            this.table.AddRow("Attr. Data Flags", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 12, 2).Replace("-", " "), maxLength), "data"); //needs function
            this.table.AddRow("Attr. ID", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 14, 2).Replace("-", " "), maxLength), BitConverter.ToInt16(mftEntry, currentOffset + 14));
        }

        public string standardInfo(byte[] mftEntry, int currentOffset)
        {
            int maxLength = Math.Max(10, Console.WindowWidth / 4);

            this.table.AddRow("File Creation", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 24, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 24)));
            this.table.AddRow("File Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 32, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 32)));
            this.table.AddRow("MFT Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 40, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 40)));
            this.table.AddRow("File Accessed", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 48, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 48)));
            this.table.AddRow("Attribute Flags", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 56, 4).Replace("-", " "), maxLength), "data"); //needs function
            this.table.AddRow("Max Versions", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 60, 4).Replace("-", " "), maxLength), "Unknown");
            this.table.AddRow("Version Number", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 64, 4).Replace("-", " "), maxLength), "Unknown");
            this.table.AddRow("Class Identifier", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 68, 4).Replace("-", " "), maxLength), "Unknown");
            this.table.AddRow("Owner Identifier", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 72, 4).Replace("-", " "), maxLength), "Unknown");
            this.table.AddRow("Security Identifier", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 76, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 76)); //needs work
            this.table.AddRow("Quota Changed", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 80, 8).Replace("-", " "), maxLength), "Unknown");
            this.table.AddRow("Update Sequence Number", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 88, 8).Replace("-", " "), maxLength), "Unknown");
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

            this.table.AddRow("Parent MFT Referece", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 24, 6).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 24));
            this.table.AddRow("File Creation", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 32, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 32)));
            this.table.AddRow("File Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 40, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 40)));
            this.table.AddRow("MFT Modification", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 48, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 48)));
            this.table.AddRow("File Accessed", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 56, 8).Replace("-", " "), maxLength), DateTime.FromFileTime(BitConverter.ToInt64(mftEntry, currentOffset + 56)));
            this.table.AddRow("Logical File Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 64, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 64));
            this.table.AddRow("Physical File Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 72, 8).Replace("-", " "), maxLength), BitConverter.ToUInt64(mftEntry, currentOffset + 72));
            this.table.AddRow("Attribute Flags", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 80, 4).Replace("-", " "), maxLength), "data"); //needs function
            this.table.AddRow("Extended Attribute Data", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 84, 4).Replace("-", " "), maxLength), BitConverter.ToInt32(mftEntry, currentOffset + 84));
            this.table.AddRow("Name Size", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 88, 1).Replace("-", " "), maxLength), nameSize.ToString());
            this.table.AddRow("File Name", tableLogic.Truncate(BitConverter.ToString(mftEntry, currentOffset + 90, nameSize).Replace("-", " "), maxLength), fileName);

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
                return table.ToMinimalString();
            }
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
