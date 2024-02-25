
// This is a refactor for MFTAnalyzer by CyberYom
// MFTAnalyzer was origonally written in Python, and is currently being refactored in C#
// This project lives in Github

using System;
using System.IO;
using System.Collections.Concurrent;
using System.ComponentModel.Design;
using System.Text;
using System.Threading.Channels;
using System.Xml;
using System.Security.Cryptography;

namespace MFTAnalyzer
{
    class Logic
    {
        static readonly byte[] targetBytes = { 0x46, 0x49, 0x4C, 0x45 }; // FILE header

        //dictionary of attrs
        static readonly Dictionary<int, string> attrTypeMap = new Dictionary<int, string>
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

        //function will extract all MFT files based on FILE header and logical size
        public static void extractMFT(string filePath)
        {
            if (!File.Exists(filePath))
            {
                Console.WriteLine("File does not exist");
                return;
            }

            byte[] fileBytes = File.ReadAllBytes(filePath);
            int startSearchOffset = 0;
            bool foundAny = false;

            while (startSearchOffset < fileBytes.Length)
            {
                //used to dynamically update offset
                int offset = FindTargetBytesOffset(fileBytes, targetBytes, startSearchOffset);

                //find the logical size of the entry
                int logicalSizeBytesOffset = offset + targetBytes.Length + 20;
                byte[] logicalSizeBytes = new byte[4];
                Array.Copy(fileBytes, logicalSizeBytesOffset, logicalSizeBytes, 0, 4);
                int logicalSize = BitConverter.ToInt32(logicalSizeBytes, 0);

                //find the first attribute
                int firstAttrBytesOffset = offset + targetBytes.Length + 16;
                byte[] firstAttrBytes = new byte[2];
                Array.Copy(fileBytes, firstAttrBytesOffset, firstAttrBytes, 0, 2);
                short firstAttr = BitConverter.ToInt16(firstAttrBytes, 0);

                //find MFT entry number
                int mftNumberBytesOffset = offset + targetBytes.Length + 40;
                byte[] mftNumberBytes = new byte[4];
                Array.Copy(fileBytes, mftNumberBytesOffset, mftNumberBytes, 0, 4);
                uint mftNumber = BitConverter.ToUInt32(mftNumberBytes, 0);

                if (offset == -1)
                {
                    if (!foundAny) Console.WriteLine("No MFT Entry extracted or an error occurred.");
                    return;
                }
                foundAny = true;

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

                //carves each mft entry
                byte[] mftEntry = new byte[logicalSize];
                Array.Copy(fileBytes, offset, mftEntry, 0, logicalSize);
                startSearchOffset = offset + logicalSize;

                //this function will parse entry header + each attr
                parseAttrs(mftEntry, mftNumber, firstAttr, logicalSize, fileBytes);
            }
        }

        static string parseAttrs(byte[] mftEntry, uint mftNumber, short firstAttr, int logicalSize, byte[] fileBytes)
        {
            //Header for each entry
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write("     Entry Header for File: ");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write(mftNumber);
            Console.ResetColor();
            Console.WriteLine();

            tableCreation tableInstance = new tableCreation(); //initialize class
            tableInstance.entryHeader(mftEntry); //start by processing entry header

            int currentOffset = firstAttr;


            while (currentOffset < logicalSize && currentOffset + 4 < mftEntry.Length)
            {
                int attrType = BitConverter.ToInt32(mftEntry, currentOffset);
                if (attrType == -1)
                    break;

                string attrTypeName;

                if (attrTypeMap.TryGetValue(attrType, out attrTypeName))
                {
                    switch (attrTypeName)
                    {
                        case "$STANDARD_INFORMATION":
                            Console.WriteLine("Attribute Type: $STANDARD_INFORMATION, " + "Current Offset:" + currentOffset);
                            tableInstance.attrHeader(mftEntry, currentOffset, attrTypeName);
                            tableInstance.standardInfo(mftEntry, currentOffset);
                            break;

                        case "$ATTRIBUTE_LIST":
                            Console.WriteLine("Attribute Type: $ATTRIBUTE_LIST, " + "Current Offset:" + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.attrList(mftEntry, currentOffset);
                            break;

                        case "$FILE_NAME":
                            Console.WriteLine("Attribute Type: $FILE_NAME, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.fileName(mftEntry, currentOffset);
                            int nameSize = mftEntry[currentOffset + 88];
                            string fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2);

                            break;

                        case "$OBJECT_ID":
                            Console.WriteLine("Attribute Type: $OBJECT_ID, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.objectID(mftEntry, currentOffset);
                            break;

                        case "$SECURITY_DESCRIPTOR":
                            Console.WriteLine("Attribute Type: $SECURITY_DESCRIPTOR, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.securityDescriptor(mftEntry, currentOffset);
                            break;

                        case "$VOLUME_NAME":
                            Console.WriteLine("Attribute Type: $VOLUME_NAME, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.volumeName(mftEntry, currentOffset);
                            break;

                        case "$VOLUME_INFORMATION":
                            Console.WriteLine("Attribute Type: $VOLUME_INFORMATION, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.volumeInformation(mftEntry, currentOffset);
                            break;

                        case "$DATA":
                            Console.WriteLine("Attribute Type: $DATA, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.data(mftEntry, currentOffset);
                            break;

                        case "$INDEX_ROOT":
                            Console.WriteLine("Attribute Type: $INDEX_ROOT, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.indexRoot(mftEntry, currentOffset);
                            break;

                        case "$INDEX_ALLOCATION":
                            Console.WriteLine("Attribute Type: $INDEX_ALLOCATION, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.indexAllocation(mftEntry, currentOffset);
                            break;

                        case "$BITMAP":
                            Console.WriteLine("Attribute Type: $BITMAP, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.bitmap(mftEntry, currentOffset);
                            break;

                        case "$REPARSE_POINT":
                            Console.WriteLine("Attribute Type: $REPARSE_POINT, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.reparsePoint(mftEntry, currentOffset);
                            break;

                        case "$EA_INFORMATION":
                            Console.WriteLine("Attribute Type: $EA_INFORMATION, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.eaInformation(mftEntry, currentOffset);
                            break;

                        case "$EA":
                            Console.WriteLine("Attribute Type: $EA, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.ea(mftEntry, currentOffset);
                            break;

                        case "$PROPERTY_SET":
                            Console.WriteLine("Attribute Type: $PROPERTY_SET, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.propertySet(mftEntry, currentOffset);
                            break;

                        case "$LOGGED_UTILITY_STREAM":
                            Console.WriteLine("Attribute Type: $LOGGED_UTILITY_STREAM, " + "Current Offset: " + currentOffset);
                            tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                            tableInstance.loggedUtilityStream(mftEntry, currentOffset);
                            break;
                    }
                }
                else
                {
                    Console.WriteLine("Unknown attribute type detected.");
                }
                // Get the length of the current attribute for moving to the next one
                int attrLength = BitConverter.ToInt32(mftEntry, currentOffset + 4);
                if (attrLength <= 0) // Sanity check to prevent infinite loop
                    break;
                currentOffset += attrLength; // Move to the next attribute

                if (currentOffset >= logicalSize) // Safety check
                    break;
            }
            return null;
        }

        private static int FindTargetBytesOffset(byte[] fileBytes, byte[] targetBytes, int startOffset)
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
            Console.WriteLine(@"                    by CyberYom");
        }
        static void firstRun()
        {
            Console.WriteLine("\nWelcome to MFT Analyzer.This tool is designed to parse and display MFT metadata. \nPassing - h will display a help menu.");
        }
        static void help()
        {
            Console.WriteLine("\n+------------------------------------+ Help Page +------------------------------------+\n");
            Console.WriteLine("Info:\n| This tool is meant to gather and parse data from the NTFS file $MTF. \n| It is intended to display results of all data in table format, \n| offering both readable and raw data.\n");
            Console.WriteLine("| To parse an MFT file, simple pass an MFT file to the tool\n└───────./MFTAnalyzer.exe C:\\path\\to\\$MFT\n\n");
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
            asciiArt();

            switch (args.Length)
            {
                case 0:
                    firstRun();
                    break;

                case 1 when args[0] != "-h":
                    Console.WriteLine("| Version: 1.0.0\n| https://github.com/cyberyom/MFTAnalyzer\n└---------------------------------------------------------------------------\n");
                    string argPath = args[0];
                    string fullPath = Path.GetFullPath(argPath);
                    Logic.extractMFT(fullPath);
                    break;

                default:
                    if (args.Contains("-h"))
                    {
                        help();
                    }
                    else
                    {
                        Console.WriteLine("Not a valid flag.");
                    }
                    break;
            }
        }
    }
}
