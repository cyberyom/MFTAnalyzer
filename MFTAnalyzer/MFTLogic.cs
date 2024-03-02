using System;
using System.Linq;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.ComponentModel.Design;
using System.Threading.Channels;
using System.Xml;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.IO.Enumeration;
using System.Threading;

namespace MFTAnalyzer
{
    public class Logic
    {
        static readonly byte[] targetBytes = { 0x46, 0x49, 0x4C, 0x45 }; // FILE header

        public static readonly Dictionary<int, string> attrTypeMap = new Dictionary<int, string> // dictionary of MFT Attributes
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

        public static List<byte[]> extractMFT(string filePath, string searchName, int searchMFTNumber, bool? shell) //first processing period, this will extract all mft entries from a file passed 
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
            int entryCounter = 0;

            while (startSearchOffset < fileBytes.Length)
            {
                entryCounter++;

                int offset = findOffset(fileBytes, targetBytes, startSearchOffset); // loops to find all FILE headers

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

            if (shell == true) { Console.WriteLine("    Total Number of MFT Entries Carved: " + entryCounter + "\n"); } //counter
            if (shell == true) { Thread.Sleep(1000); } //pause before moving on, adds 1 second of processing time
            if (shell == true) { Console.WriteLine("    Analyzing MFT Entries...\n"); } // verbosity for console output, indicia
                                                                                        // this is becayse certian variables can be passed and certian ones wont be

            parseMFT(mftEntries, searchName, searchMFTNumber, shell);
            return mftEntries;
        }

        public static void parseMFT(List<byte[]> mftEntries, string searchName, int searchMFTNumber, bool? shell) // this function sets variables needed to parse mft entries. Maybe this is faster inside of parse Attrs) // this function sets variables needed to parse mft entries. Maybe this is faster inside of parse Attrs
        {
            foreach (var mftEntry in mftEntries)
            {
                short firstAttr = BitConverter.ToInt16(mftEntry, 20);
                int logicalSize = BitConverter.ToInt32(mftEntry, 24);
                uint mftNumber = BitConverter.ToUInt32(mftEntry, 44);
                bool matchFound = false;

                parseAttrs(mftEntry, firstAttr, logicalSize, mftNumber, searchName, searchMFTNumber, shell, mftEntries);

                if (matchFound)
                {
                    break; // Add only matched entries to the list
                }
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

        public static bool parseAttrs(byte[] mftEntry, short firstAttr, int logicalSize, uint mftNumber, string searchName, int searchMFTNumber, bool? shell, List<byte[]> mftEntries) // main function that builds the tables and rebuilds the filesystem
        {
            tableCreation tableInstance = new tableCreation(); //initialize class
            StringBuilder mftTable = new StringBuilder(); //create string called mft table using string  builder, for all the tables below
            string fileName = "";
            bool fileNameMatched = false;
            string entryTable; //initialize empty string
            int currentOffset = firstAttr;

            if (shell != true)
            {
                entryTable = tableInstance.entryHeader(mftEntry); // pass entryheader to table instance (this is the template for the entry header)
                mftTable.Append(entryTable); //add the table to mftTable
            }

            while (currentOffset < logicalSize && currentOffset + 4 < mftEntry.Length) //starts while loop to process all mft entries
            {
                int attrType = BitConverter.ToInt32(mftEntry, currentOffset); // sets the attribute type bytes to attrtype as integer 

                if (attrType == -1)
                    break;

                string attrTypeName;

                if (attrTypeMap.TryGetValue(attrType, out attrTypeName)) // dictionary at top of class 'logic'
                {
                    if (attrTypeName == "$FILE_NAME")
                    {
                        int nameSize = mftEntry[currentOffset + 88];
                        fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2);
                        if (!string.IsNullOrEmpty(searchName) && fileName.Equals(searchName, StringComparison.OrdinalIgnoreCase))
                        {
                            fileNameMatched = true;
                            // Optionally, break here if you only need the first match
                        }
                    }

                    switch (attrTypeName) //switch statement to handle all attributes. Note that this was a recent focus, and some things are old and new
                    {
                        case "$STANDARD_INFORMATION":
                            tableInstance.attrHeader(mftEntry, currentOffset, attrTypeName);
                            string standardInfo = tableInstance.standardInfo(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $STANDARD_INFORMATION\n" + standardInfo + "\n"); }
                            break;

                        case "$ATTRIBUTE_LIST":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string attributeList = tableInstance.attrList(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $ATTRIBUTE_LIST\n" + attributeList + "\n"); }
                            break;

                        case "$FILE_NAME": //this needs to be here in order to accurately parse the attributes (I think)
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            int nameSize = mftEntry[currentOffset + 88];
                            fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2); //needed to define thig again as fileName and fileSize was defined outside of the current scope
                            string fileNameTable = tableInstance.fileName(mftEntry, currentOffset);
                            int parentMFTnumber = BitConverter.ToInt32(mftEntry, currentOffset + 24);
                            if (shell != true) { mftTable.Append("\n Attribute: $FILE_NAME\n" + fileNameTable + "\n"); }

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
                            if (shell != true) { mftTable.Append("\n Attribute: $OBJECT_ID\n" + objectID + "\n"); }
                            break;

                        case "$SECURITY_DESCRIPTOR":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string securityDescriptor = tableInstance.securityDescriptor(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $SECURITY_DESCRIPTOR\n" + securityDescriptor + "\n"); }
                            break;

                        case "$VOLUME_NAME":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string volumeName = tableInstance.volumeName(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $VOLUME_NAME\n" + volumeName + "\n"); }
                            break;

                        case "$VOLUME_INFORMATION":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string volumeInformation = tableInstance.volumeInformation(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $VOLUME_INFORMATION\n" + volumeInformation + "\n"); }
                            break;

                        case "$DATA":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string data = tableInstance.data(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $DATA\n" + data + "\n"); }
                            break;

                        case "$INDEX_ROOT":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string indexRoot = tableInstance.indexRoot(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $INDEX_ROOT\n" + indexRoot + "\n"); }
                            break;

                        case "$INDEX_ALLOCATION":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string indexAllocation = tableInstance.indexAllocation(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $INDEX_ALLOCATION\n" + indexAllocation + "\n"); }
                            break;

                        case "$BITMAP":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string bitmap = tableInstance.bitmap(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $BITMAP\n" + bitmap + "\n"); }
                            break;

                        case "$REPARSE_POINT":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string reparsePoint = tableInstance.reparsePoint(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $REPARSE_POINT\n" + reparsePoint + "\n"); }
                            break;

                        case "$EA_INFORMATION":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string eaInformation = tableInstance.eaInformation(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $EA_INFORMATION\n" + eaInformation + "\n"); }
                            break;

                        case "$EA":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string ea = tableInstance.ea(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $EA\n" + ea + "\n"); }
                            break;

                        case "$PROPERTY_SET":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string propertySet = tableInstance.propertySet(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $PROPERTY_SET\n" + propertySet + "\n"); }
                            break;

                        case "$LOGGED_UTILITY_STREAM":
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            string loggedUtilityStream = tableInstance.loggedUtilityStream(mftEntry, currentOffset);
                            if (shell != true) { mftTable.Append("\n Attribute: $LOGGED_UTILITY_STREAM\n" + loggedUtilityStream + "\n"); }
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
            if (!string.IsNullOrEmpty(searchName) && fileNameMatched)
            {
                Console.WriteLine("     Showing MFT Entry for file: " + fileName + " - MFT Entry: " + mftNumber);
                Console.WriteLine(mftTable34);
                return true;
            }
            else if (searchMFTNumber >= 0 && mftNumber != searchMFTNumber)
            {
                return false; // MFT number does not match, skip processing
            }
            else if (!string.IsNullOrEmpty(searchName))
            {
                return false;
            }
            else if (shell == true) { return false; }
            
            else
            {
                Console.WriteLine("     Showing MFT Entry for file: " + fileName + " - MFT Entry: " + mftNumber);
                Console.WriteLine(mftTable);
                return false;
            }
        }

        static int findOffset(byte[] fileBytes, byte[] targetBytes, int startOffset) // used to find all instances of FILE header for entry
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
}
