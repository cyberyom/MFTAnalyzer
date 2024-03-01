
// This is a refactor for MFTAnalyzer by CyberYom
// MFTAnalyzer was origonally written in Python, and is currently being refactored in C#
// This project lives in Github

using System;
using System.IO;
using System.Diagnostics; 
using System.Collections.Concurrent;
using System.ComponentModel.Design;
using System.Text;
using System.Threading.Channels;
using System.Xml;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO.Enumeration;

namespace MFTAnalyzer
{
    public class Logic
    {
        static readonly byte[] targetBytes = { 0x46, 0x49, 0x4C, 0x45 }; // FILE header

        static readonly Dictionary<int, string> attrTypeMap = new Dictionary<int, string> // dictionary of MFT Attributes
        {
            { 0x10, "$STANDARD_INFORMATION" },
            { 0x20, "$ATTRIBUTE_LIST" },
            { 0x30, "$FILE_NAME" },
            { 0x40, "$OBJECT_ID" },
            { 0x50, "$SECURITY_DESCRIPTOR" },
            { 0x60, "$VOLUME_NAME" },
            { 0x70, "$VOLUME_INFORMATION" },
            { 0x80, "$DATA" },
            { 0x90, "$INDEX_ROOT" },
            { 0xA0, "$INDEX_ALLOCATION" },
            { 0xB0, "$BITMAP" },
            { 0xC0, "$REPARSE_POINT" },
            { 0xD0, "$EA_INFORMATION" },
            { 0xE0, "$EA" },
            { 0xF0, "$PROPERTY_SET" },
        };

        public static List<byte[]> extractMFT(string filePath, bool? searchName, bool? searchMFT, bool? shell) //first processing period, this will extract all mft entries from a file passed 
        {
            if (shell == true) { Console.WriteLine("    Carving MFT Entries...\n"); } // verbose output indiciation start of function (only if shell = true)

            List<byte[]> mftEntries = new List<byte[]>(); // make list for mft entries


            if (!File.Exists(filePath))
            {
                Console.WriteLine("File does not exist");
                return mftEntries; // check for file
            }

            //Initialize variables for processing
            byte[] fileBytes = File.ReadAllBytes(filePath);
            int startSearchOffset = 0;
            bool foundAny = false;

            while (startSearchOffset < fileBytes.Length)
            {
                int offset = FindTargetBytesOffset(fileBytes, targetBytes, startSearchOffset); // loops to find all FILE headers

                if (offset == -1)
                {
                    if (!foundAny) Console.WriteLine("No MFT Entry extracted or an error occurred.");
                    break;
                }

                foundAny = true;

                //find the logical size of the entry
                int logicalSizeBytesOffset = offset + targetBytes.Length + 20;
                byte[] logicalSizeBytes = new byte[4];
                Array.Copy(fileBytes, logicalSizeBytesOffset, logicalSizeBytes, 0, 4);
                int logicalSize = BitConverter.ToInt32(logicalSizeBytes, 0);

                //carves each mft entry
                byte[] mftEntry = new byte[logicalSize];
                Array.Copy(fileBytes, offset, mftEntry, 0, logicalSize);
                startSearchOffset = offset + logicalSize;
                mftEntries.Add(mftEntry);

                if (logicalSizeBytesOffset + 4 > fileBytes.Length)
                {
                    Console.WriteLine("The specified range exceeds the file's length.");
                    break;
                }

                if (offset + logicalSize > fileBytes.Length)
                {
                    Console.WriteLine("Attempting to read beyond the file's end.");
                    break;
                }
            }

            if (shell == true) { Console.WriteLine("    Analyzing MFT Entries...\n"); } // verbosity for console output, indiciates the start of parse MFT
            // this is becayse certian variables can be passed and certian ones wont be
            if (searchName == true) { parseMFT(mftEntries, searchName, null, null); } 
            else if (searchMFT == true) { parseMFT(mftEntries, null, searchMFT, null); }
            else if (shell == true) { parseMFT(mftEntries, null, null, shell); }
            else parseMFT(mftEntries, null, null, null);

            return mftEntries;
        }

        public static void parseMFT(List<byte[]> mftEntries, bool? searchName, bool? searchMFT, bool? shell) // this function sets variables needed to parse mft entries. Maybe this is faster inside of parse Attrs
        {
            foreach (var mftEntry in mftEntries)
            {
                short firstAttr = BitConverter.ToInt16(mftEntry, 20);
                int logicalSize = BitConverter.ToInt32(mftEntry, 24);
                uint mftNumber = BitConverter.ToUInt32(mftEntry, 44);

                if (shell == true) { parseAttrs(mftEntry, firstAttr, logicalSize, mftNumber, null, null, shell); }
                else if (searchName == true) { parseAttrs(mftEntry, firstAttr, logicalSize, mftNumber, searchName, null, null); }
                else if (searchMFT == true) { parseAttrs(mftEntry, firstAttr, logicalSize, mftNumber, null, searchMFT, null); }
                else parseAttrs(mftEntry, firstAttr, logicalSize, mftNumber, null, null, null);
            }
        }

        public static Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem = new Dictionary<int, List<(string, int)>>(); // Dictionary initialization for SHELL (only gets populated if shell is enabled)
        public static void DisplayContents(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, int mftFolder, HashSet<int> seenEntries = null) // function used for commands in shell mode (needs to be here in this function because of MFT entry offsets)
        {
            if (seenEntries == null) seenEntries = new HashSet<int>();

            if (!filesystem.ContainsKey(mftFolder))
            {
                Console.WriteLine("Folder not found.");
                return;
            }

            var contents = filesystem[mftFolder];
            foreach (var item in contents)
            {
                if (!seenEntries.Add(item.entryNumber))
                {
                    continue; // Skip this item if it has already been processed
                }

                Console.WriteLine($"{item.extractedName} (Entry: {item.entryNumber})");
            }
        }

        public static string parseAttrs(byte[] mftEntry, short firstAttr, int logicalSize, uint mftNumber, bool? searchName, bool? searchMFT, bool? shell) // main function that builds the tables and rebuilds the filesystem
        {
            tableCreation tableInstance = new tableCreation(); //initialize class
            StringBuilder mftTable = new StringBuilder(); //create string called mft table using string  builder, for all the tables below

            string entryTable = ""; //initialize empty string

            if (shell != true)
            {
                entryTable = tableInstance.entryHeader(mftEntry); // pass entryheader to table instance (this is the template for the entry header)
                mftTable.Append(entryTable); //add the table to mftTable
            }

            int currentOffset = firstAttr; //sets first attribute offset to currentoffset 


            while (currentOffset < logicalSize && currentOffset + 4 < mftEntry.Length) //starts while loop to process all mft entries
            {
                int attrType = BitConverter.ToInt32(mftEntry, currentOffset); // sets the attribute type bytes to attrtype as integer 

                if (attrType == -1)
                    break;

                string attrTypeName;

                if (attrTypeMap.TryGetValue(attrType, out attrTypeName)) // dictionary at top of class 'logic'
                {
                    //try to extract filename and print for header
                    if (attrTypeName.Contains ("$FILE_NAME") && shell != true) //this needs to be like this. This was very crafty and sneaky, and conceptually difficult to figure out
                    {
                        int nameSize = mftEntry[currentOffset + 88];
                        string fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2);
                        Console.WriteLine("     Showing MFT Entry for file: " + fileName + " - MFT Entry: " + mftNumber);
                    }

                    switch (attrTypeName) //switch statement to handle all attributes. Note that this was a recent focus, and some things are old and new
                    { 
                        case "$STANDARD_INFORMATION":
                            tableInstance.attrHeader(mftEntry, currentOffset, attrTypeName);
                            string standardInfo = tableInstance.standardInfo(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                mftTable.Append("\n Attribute: $STANDARD_INFORMATION\n" + standardInfo + "\n"); //new way to do handle the table (add to mftTable)
                            }
                            break;

                        case "$ATTRIBUTE_LIST":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string attributeList = tableInstance.attrList(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute: $ATTRIBUTE_LIST" + attributeList); // old way to handle table (print directly to screen)
                            }
                            break;

                        case "$FILE_NAME": //this needs to be here in order to accurately parse the attributes (I think)
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            int nameSize = mftEntry[currentOffset + 88];
                            string fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2); //needed to define thig again as fileName and fileSize was defined outside of the current scope
                            string fileNameTable = tableInstance.fileName(mftEntry, currentOffset);
                            int parentMFTnumber = BitConverter.ToInt32(mftEntry, currentOffset + 24);
                            if (shell != true)
                            {
                                mftTable.Append("\n Attribute: $FILE_NAME\n" + fileNameTable + "\n");
                            }

                            if (!filesystem.ContainsKey(parentMFTnumber)) 
                            {
                                filesystem[parentMFTnumber] = new List<(string, int)>();
                            }
                                
                            int mftNumberInt = unchecked((int)mftNumber);
                            filesystem[parentMFTnumber].Add((fileName, mftNumberInt));

                            break;

                        case "$OBJECT_ID":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string objectID = tableInstance.objectID(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(objectID);
                            }
                            break;

                        case "$SECURITY_DESCRIPTOR":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string securityDescriptor = tableInstance.securityDescriptor(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $SECURITY_DESCRIPTOR");
                                Console.WriteLine(securityDescriptor);
                            }
                            break;

                        case "$VOLUME_NAME":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string volumeName = tableInstance.volumeName(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $VOLUME_NAME");
                                Console.WriteLine(volumeName);
                            }
                            break;

                        case "$VOLUME_INFORMATION":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string volumeInformation = tableInstance.volumeInformation(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $VOLUME_INFORMATION");
                                Console.WriteLine(volumeInformation);
                            }
                            break;

                        case "$DATA":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string data = tableInstance.data(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                mftTable.Append("\n Attribute: $DATA\n" + data + "\n");
                            }
                            break;

                        case "$INDEX_ROOT":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string indexRoot = tableInstance.indexRoot(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $INDEX_ROOT");
                                Console.WriteLine(indexRoot);
                            }
                            break;

                        case "$INDEX_ALLOCATION":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string indexAllocation = tableInstance.indexAllocation(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $INDEX_ALLOCATION");
                                Console.WriteLine(indexAllocation);
                            }
                            break;

                        case "$BITMAP":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string bitmap = tableInstance.bitmap(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                mftTable.Append("\n Attribute: $BITMAP\n" + bitmap + "\n");
                            }
                            break;

                        case "$REPARSE_POINT":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string reparsePoint = tableInstance.reparsePoint(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $REPARSE_POINT");
                                Console.WriteLine(reparsePoint);
                            }
                            break;

                        case "$EA_INFORMATION":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string eaInformation = tableInstance.eaInformation(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $EA_INFORMATION");
                                Console.WriteLine(eaInformation);
                            }
                            break;

                        case "$EA":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string ea = tableInstance.ea(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $EA");
                                Console.WriteLine(ea);
                            }
                            break;

                        case "$PROPERTY_SET":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string propertySet = tableInstance.propertySet(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $PROPERTY_SET");
                                Console.WriteLine(propertySet);
                            }
                            break;

                        case "$LOGGED_UTILITY_STREAM":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string loggedUtilityStream = tableInstance.loggedUtilityStream(mftEntry, currentOffset);
                            if (shell != true)
                            {
                                Console.WriteLine(" Attribute Type: $LOGGED_UTILITY_STREAM");
                                Console.WriteLine(loggedUtilityStream);
                            }
                            break;
                    }
                }
                int attrLength = BitConverter.ToInt32(mftEntry, currentOffset + 4); 
                if (attrLength <= 0) // Sanity check to prevent infinite loop
                    break;
                currentOffset += attrLength; // Move to the next attribute

                if (currentOffset >= logicalSize) // Safety check
                    break;
            }
            if (shell != true)
            {
                Console.WriteLine(mftTable); // prints mftTable
            }
            return null;
        }

        private static int FindTargetBytesOffset(byte[] fileBytes, byte[] targetBytes, int startOffset) // used to find all instances of FILE header for entry
        {
            for (int i = startOffset; i <= fileBytes.Length - targetBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < targetBytes.Length; j++)
                {
                    if (fileBytes[i + j] != targetBytes[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) return i;
            }
            return -1;
        }
    }

    class Execution
    {
        static void asciiArt()
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"
        M   M  FFFFF  TTTTT  
        MM MM  F        T    
        M M M  FFF      T    
        M   M  F        T    
        M   M  F        T ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"
AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ  EEEEE  RRRRR  
A   A  NN  N  A   A  L      Y Y      Z    E      R   R 
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR  
A   A  N  NN  A   A  L       Y     Z      E      R R   
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR 
    ");
            Console.ResetColor();
            Console.WriteLine(@"             by CyberYom");
        }

        static void firstRun()
        {
            Console.WriteLine("\nWelcome to MFT Analyzer. This tool is designed to parse and display MFT metadata. \nPassing -h will display a help menu.");
        }

        static void help()
        {
            Console.WriteLine("\n+------------------------------------+ Help Page +------------------------------------+\n");
            Console.WriteLine("Info:\n| This tool is meant to gather and parse data from the NTFS file $MTF. \n| It is intended to display results of all data in table format, \n| offering both readable and raw data.\n");
            Console.WriteLine("| To parse an MFT file, simply pass an MFT file to the tool\n└───────./MFTAnalyzer.exe C:\\path\\to\\$MFT\n\n");
            Console.WriteLine("Flags:");
            Console.WriteLine("| -sn \n└───────./MFTAnalyzer.exe $MFT -sn filename\n\t- Search for a specific file entry based off file name\n");
            Console.WriteLine("| -sm \n└───────./MFTAnalyzer.exe $MFT -sm ENTRYNUMBER\n\t- Search for a specific file entry based off MFT file entry number\n");
            Console.WriteLine("| --shell \n└───────./MFTAnalyzer.exe $MFT --shell\n\t- Enter a shell with the MFT file\n\n");
            Console.WriteLine("Additional help:\n|Support:\n└───────https://github.com/cyberyom/MFTAnalyzer/issues\n\n");
            Console.WriteLine("Version: 1.0.0");
            Console.WriteLine("Author: CyberYom");
            Console.WriteLine("https://github.com/cyberyom/MFTAnalyzer");
        }

        static void Main(string[] args)
        {
            bool shellArgumentPresent = args.Contains("--shell");
            asciiArt();

            // setting strings to initialize $MFT passed
            string filePath = args.Length > 0 ? args[0] : null;
            string fullPath = filePath != null ? Path.GetFullPath(filePath) : null;

            if (args.Length == 1 && args[0] == "-h")
            {
                help();
            }
            else if (shellArgumentPresent)
            {
                ProcessShellArgument(fullPath); // Process shell argument separately, as this wont output anything to screen
            }
            else
            {
                ProcessFlags(args, fullPath); // Handle other arguments, not added yet tho
            }
        }

        static void ProcessShellArgument(string fullPath)
        {
            Console.WriteLine("| Version: 1.0.0\n| https://github.com/cyberyom/MFTAnalyzer\n└---------------------------------------------------------------------------");
            if (fullPath != null)
            {
                WarnIfLargeFile(fullPath); // Warn if the file is large
                Logic.extractMFT(fullPath, null, null, true); // Pass true for the shell flag
            }
            Shell.RunShell(); // Start the shell after processing the MFT
        }

        static void ProcessFlags(string[] args, string fullPath)
        {
            bool? searchName = Array.IndexOf(args, "-sn") != -1 ? true : null;
            bool? searchMFT = Array.IndexOf(args, "-sm") != -1 ? true : null;

            if (fullPath != null && !args.Contains("--shell"))
            {
                WarnIfLargeFile(fullPath); // Warn if the file is large, applicable for non-shell operations too
                Logic.extractMFT(fullPath, searchName, searchMFT, false); // shell flag false, as this is in the else statement
            }
        }

        static void WarnIfLargeFile(string filePath)
        {
            FileInfo fileInfo = new FileInfo(filePath);
            long sizeInBytes = fileInfo.Length;
            const long thresholdSize = 100000000; // 100 MB 

            if (sizeInBytes > thresholdSize)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("Warning");
                Console.ResetColor();
                Console.Write($": The file you are trying to parse is large (");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write(sizeInBytes);
                Console.ResetColor();
                Console.WriteLine(" bytes). Processing may take some time.\n");
            }
        }
    }
}
