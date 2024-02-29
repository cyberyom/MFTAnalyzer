
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

namespace MFTAnalyzer
{
    public class Shell
    {
        static void help()
        {
            Console.WriteLine("     Available Commands:");
            Console.WriteLine("help\n└────── Display the help menu\n");
            Console.WriteLine("tree\n└────── Display the file structure of current directory and below. Note that 'tree .' can be used to view the whole disk\n");
            Console.WriteLine("ls\n└────── View the contents of a Directory\n");
            Console.WriteLine("cat\n└────── View MFT entry for file\n");
            Console.WriteLine("find\n└────── Find MFT entry for specific file\n");
            Console.WriteLine("dump\n└────── Dump the contents of resident files, for non-resident files, return offsets for carving\n");
            Console.WriteLine("clear\n└────── Clear the screen\n");
            Console.WriteLine("exit\n└────── Exit the shell\n");
        }
        public static int FindMFTEntryByFolderName(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, string folderName)
        {
            foreach (var entry in filesystem)
            {
                foreach (var file in entry.Value)
                {
                    if (file.extractedName.Equals(folderName, StringComparison.OrdinalIgnoreCase))
                    {
                        return file.entryNumber; // Return the MFT entry number
                    }
                }
            }
            return -1; // Indicate that the folder was not found
        }

        public static void FindFilePaths(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, string filename, int entryNumber, string currentPath, HashSet<string> foundPaths)
        {
            if (!filesystem.ContainsKey(entryNumber))
            {
                return; // Directory does not exist in the filesystem
            }

            foreach (var item in filesystem[entryNumber])
            {
                // Construct the path for this item
                string itemPath = currentPath == "" ? item.extractedName : $"/{currentPath}/{item.extractedName}";

                if (item.extractedName.Equals(filename, StringComparison.OrdinalIgnoreCase))
                {
                    foundPaths.Add(itemPath); // Add the path to the set of found paths
                }

                // If the item is a directory, recurse into it, excluding special directories to prevent infinite recursion
                if (filesystem.ContainsKey(item.entryNumber) && !item.extractedName.Equals(".") && !item.extractedName.Equals(".."))
                {
                    FindFilePaths(filesystem, filename, item.entryNumber, itemPath, foundPaths);
                }
            }
        }
        public static void DisplayTree(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, int entryNumber, string indent = "", HashSet<string> seenPaths = null, string currentPath = "", bool isRoot = true)
{
            // Initialize the HashSet on the first call or when not provided
            if (seenPaths == null) seenPaths = new HashSet<string>();

            // Check if this is the root and handle it accordingly
            if (isRoot)
            {
                Console.WriteLine(".");
                isRoot = false; // Only the root should be marked as such, subsequent items are not root
            }

            if (!filesystem.ContainsKey(entryNumber))
            {
                Console.WriteLine($"{indent}[Folder not found]");
                return;
            }

            var filesAndFolders = filesystem[entryNumber];
            int count = filesAndFolders.Count;
            for (int i = 0; i < count; i++)
            {
                var item = filesAndFolders[i];
                // Construct the unique path for this item
                string itemPath = currentPath == "/" ? $"{currentPath}{item.extractedName}" : $"{currentPath}/{item.extractedName}";

                // Check if we've already processed this path to avoid duplication and to prevent parsing the root directory (.) again
                if (!seenPaths.Add(itemPath) || (item.extractedName.Equals(".") && !isRoot))
                {
                    continue; // Skip if already processed or if it's the root directory being processed again
                }

                bool isFolder = filesystem.ContainsKey(item.entryNumber);
                if (isFolder)
                {
                    // Determine the appropriate indent for this item
                    string newIndent = indent + (isRoot ? "" : "|  ");
                    // Print the connector with a branch or a corner based on item position
                    Console.WriteLine($"{indent}{(i < count - 1 ? "|--" : "`--")}{item.extractedName}/");

                    // Avoid recursion into the root directory marker (.) after the initial root handling
                    if (!item.extractedName.Equals("."))
                    {
                        // Recursively call with the updated seenPaths to track processed items and updated currentPath
                        DisplayTree(filesystem, item.entryNumber, newIndent + (i < count - 1 ? "|  " : "   "), seenPaths, itemPath, false);
                    }
                }
                else
                {
                    // Print file names with the appropriate branching or corner connector
                    Console.WriteLine($"{indent}{(i < count - 1 ? "|--" : "`--")}{item.extractedName}");
                }
            }
        }

        public static void RunShell()
        {
            var DisplayContents = Logic.DisplayContents;
            var filesystem = Logic.filesystem;
            bool isRunning = true;

                   
            while (isRunning)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write("MFT Shell");
                Console.ResetColor();
                Console.Write(" > ");
                string input = Console.ReadLine().Trim();
                string[] parts = input.Split(new[] { ' ' }, 2);
                string command = parts[0].ToLower();
                string argument = parts.Length > 1 ? parts[1] : null;

                switch (command.ToLower())
                {
                    case "exit":
                        Console.WriteLine("Exiting...");
                        isRunning = false;
                        break;

                    case "help":
                        help();
                        break;

                    case "tree":
                        int rootMFT;
                        if (string.IsNullOrWhiteSpace(argument))
                        {
                            rootMFT = 5; // Assuming root directory's MFT entry, adjust as needed
                        }
                        else
                        {
                            rootMFT = FindMFTEntryByFolderName(filesystem, argument);
                            if (rootMFT == -1)
                            {
                                Console.WriteLine($"Folder '{argument}' not found.");
                                break;
                            }
                        }
                        DisplayTree(filesystem, rootMFT);
                        break;
                        
                    case "ls":
                        int mftFolder;
                        if (string.IsNullOrWhiteSpace(argument))
                        {
                            mftFolder = 5; // Adjust this value as needed
                        }
                        else
                        {
                            mftFolder = FindMFTEntryByFolderName(filesystem, argument); // Corrected call
                            if (mftFolder == -1)
                            {
                                Console.WriteLine($"Folder '{argument}' not found.");
                                break;
                            }
                        }
                        DisplayContents(filesystem, mftFolder);
                        break;

                    case "find":
                        if (string.IsNullOrWhiteSpace(argument))
                        {
                            Console.WriteLine("Please specify a file name to find.");
                        }
                        else
                        {
                            HashSet<string> foundPaths = new HashSet<string>();
                            FindFilePaths(filesystem, argument, 5, "", foundPaths); // Assuming 5 is the root MFT entry
                            foreach (var path in foundPaths)
                            {
                                Console.WriteLine(path); // Print each unique path
                            }
                        }
                        break;

                    default:
                        if (!string.IsNullOrWhiteSpace(command))
                        {
                            Console.WriteLine($"Unknown command: {command}");
                        }
                        break;
                }
            }
        }
        public class Logic
        {
            static readonly byte[] targetBytes = { 0x46, 0x49, 0x4C, 0x45 }; // FILE header

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
            public static List<byte[]> extractMFT(string filePath, bool? searchName, bool? searchMFT, bool? shell)
            {
                List<byte[]> mftEntries = new List<byte[]>();


                if (!File.Exists(filePath))
                {
                    Console.WriteLine("File does not exist");
                    return mftEntries;
                }
                Console.WriteLine("Carving MFTs...");
                byte[] fileBytes = File.ReadAllBytes(filePath);
                int startSearchOffset = 0;
                bool foundAny = false;

                while (startSearchOffset < fileBytes.Length)
                {
                    //used to dynamically update offset
                    int offset = FindTargetBytesOffset(fileBytes, targetBytes, startSearchOffset);

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

                    //this function will parse entry header + each attr
                    // parseAttrs(mftEntry, mftNumber, firstAttr, logicalSize, fileBytes);
                }
                Console.WriteLine("Analyzing MFT Entries...");
                if (searchName == true) { parseMFT(mftEntries, searchName, null, null); }
                else if (searchMFT == true) { parseMFT(mftEntries, null, searchMFT, null); }
                else if (shell == true) { parseMFT(mftEntries, null, null, shell); }
                else parseMFT(mftEntries, null, null, null);
                return mftEntries;
            }

            public static void parseMFT(List<byte[]> mftEntries, bool? searchName, bool? searchMFT, bool? shell)
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

            public static Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem = new Dictionary<int, List<(string, int)>>();
            public static void DisplayContents(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, int mftFolder, HashSet<int> seenEntries = null)
            {
                // Initialize the HashSet on the first call
                if (seenEntries == null) seenEntries = new HashSet<int>();

                if (!filesystem.ContainsKey(mftFolder))
                {
                    Console.WriteLine("Folder not found.");
                    return;
                }

                var contents = filesystem[mftFolder];
                foreach (var item in contents)
                {
                    // Add check to ensure we don't process duplicates
                    if (!seenEntries.Add(item.entryNumber))
                    {
                        continue; // Skip this item if it has already been processed
                    }

                    Console.WriteLine($"{item.extractedName} (Entry: {item.entryNumber})");
                }
            }

            public static string parseAttrs(byte[] mftEntry, short firstAttr, int logicalSize, uint mftNumber, bool? searchName, bool? searchMFT, bool? shell)
            {
                tableCreation tableInstance = new tableCreation(); //initialize class
                if (shell != true)
                {
                    string entryTable = tableInstance.entryHeader(mftEntry); // Process entry header once, before the loop
                    Console.WriteLine("     Showing MFT Entry for: #" + mftNumber);
                    Console.WriteLine(entryTable);
                }
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
                                tableInstance.attrHeader(mftEntry, currentOffset, attrTypeName);
                                string standardInfo = tableInstance.standardInfo(mftEntry, currentOffset);
                                if (shell != true)
                                {
                                    Console.WriteLine(" Attribute Type: $STANDARD_INFORMATION");
                                    Console.WriteLine(standardInfo);
                                }
                                break;

                            case "$ATTRIBUTE_LIST":
                                tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                                string attributeList = tableInstance.attrList(mftEntry, currentOffset);
                                if (shell != true)
                                {
                                    Console.WriteLine(" Attribute Type: $ATTRIBUTE_LIST");
                                    Console.WriteLine(attributeList);
                                }
                                break;

                            case "$FILE_NAME":
                                // Previous code to handle the $FILE_NAME attribute
                                tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                                string fileNameTable = tableInstance.fileName(mftEntry, currentOffset);
                                int nameSize = mftEntry[currentOffset + 88];
                                string fileName = Encoding.Unicode.GetString(mftEntry, currentOffset + 90, nameSize * 2);
                                int parentMFTnumber = BitConverter.ToInt32(mftEntry, currentOffset + 24);
                                if (shell != true)
                                {
                                    Console.WriteLine(" Attribute Type: $FILE_NAME");
                                    Console.WriteLine(fileNameTable);
                                }

                                if (!filesystem.ContainsKey(parentMFTnumber))
                                {
                                    filesystem[parentMFTnumber] = new List<(string, int)>();
                                }
                                
                                // Convert mftNumber from uint to int before adding it to the list
                                int mftNumberInt = unchecked((int)mftNumber);
                                filesystem[parentMFTnumber].Add((fileName, mftNumberInt));

                                break;

                            case "$OBJECT_ID":
                                tableInstance.attrHeader(mftEntry, 0 + currentOffset, attrTypeName);
                                string objectID = tableInstance.objectID(mftEntry, currentOffset);
                                if (shell != true)
                                {
                                    Console.WriteLine(" Attribute Type: $OBJECT_ID");
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
                                    Console.WriteLine(" Attribute Type: $DATA");
                                    Console.WriteLine(data);
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
                                    Console.WriteLine(" Attribute Type: $BITMAP");
                                    Console.WriteLine(bitmap);
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
                asciiArt();

                switch (args.Length)
                {
                    case 0:
                        firstRun();
                        break;

                    case 1 when args[0] == "-h":
                        help();
                        break;

                    case 1 when "--shell" != args[2]:
                        Console.WriteLine("| Version: 1.0.0\n| https://github.com/cyberyom/MFTAnalyzer\n└---------------------------------------------------------------------------\n");
                        string argPath = args[0];
                        string fullPath = Path.GetFullPath(argPath);
                        Logic.extractMFT(fullPath, null, null, null);
                        break;

                    default:
                        string argPath1 = args[0];
                        string fullPath1 = Path.GetFullPath(argPath1);
                        ProcessFlags(args, fullPath1);
                        break;
                }
            }

            static void ProcessFlags(string[] args, string fullPath)
            {
                bool? searchName = Array.IndexOf(args, "-sn") != -1 ? true : null;
                bool? searchMFT = Array.IndexOf(args, "-sm") != -1 ? true : null;
                bool? shell = Array.IndexOf(args, "--shell") != -1 ? true : null;
                string filePath = null;

                foreach (var arg in args)
                {
                    if (!arg.StartsWith("-"))
                    {
                        filePath = arg; // Assuming the non-flag argument is the file path
                        break;
                    }
                }
                TextWriter originalOutput = Console.Out;

                if (shell == true)
                {
                    Console.WriteLine("| Version: 1.0.0\n| https://github.com/cyberyom/MFTAnalyzer\n└---------------------------------------------------------------------------");
                    Console.Write("Welcome to the MFT Shell. Please pass the command '");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("help");
                    Console.ResetColor();
                    Console.Write("' for more info. Type '");
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("exit");
                    Console.ResetColor();
                    Console.WriteLine("' to quit.\n");
                    if (filePath != null)
                    {
                        FileInfo fileInfo = new FileInfo(filePath);
                        long sizeInBytes = fileInfo.Length;
                        const long thresholdSize = 10000000; // 10 MB for example

                        // Check the file size and print warning if applicable
                        if (sizeInBytes > thresholdSize)
                        {
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.Write("Warning");
                            Console.ResetColor();
                            Console.WriteLine($": The file you are trying to parse is large ({sizeInBytes} bytes). Processing may take some time.");
                            Logic.extractMFT(filePath, null, null, shell); // Assuming this is a synchronous call
                            Console.WriteLine($"Rebuilding Filesystem...");
                        }
                        else
                        {
                            Logic.extractMFT(filePath, null, null, shell);
                        }
                    }
                    Console.SetOut(TextWriter.Null);
                }
                Logic.extractMFT(filePath, searchName, searchMFT, shell);
                if (shell == true)
                {
                    Console.SetOut(originalOutput);
                    Shell.RunShell();
                }
            }
        }
    }
}
