using System;
using System.Text;

namespace MFTAnalyzer
{
    public class Shell
    {
        static void help()
        {
            Console.WriteLine("\n     Available Commands:");
            Console.WriteLine("+-----------------------------------------------------------------+");
            Console.WriteLine("help\n└────── Display the help menu\n");
            Console.WriteLine("tree\n└────── Recursively display the file structure of directory passed. Used with filenames. \n");
            Console.WriteLine("ls\n└────── View the contents of a Directory. Used with file names\n");
            Console.WriteLine("find\n└────── Find MFT entry for specific file. Used with file names\n");
            Console.WriteLine("cat\n└────── View MFT entry for file. Used with MFT numbers\n");
            Console.WriteLine("carve\n└────── Carve the contents of resident files, return offsets needed to carve fir non-resident files. Used with MFT numbers.\n");
            Console.WriteLine("hexdump\n└────── View raw data for each MFT entry. Used with MFT numbers\n");
            Console.WriteLine("clear\n└────── Clear the screen\n");
            Console.WriteLine("exit\n└────── Exit the shell\n");
        }
        private static void parseMFT(List<byte[]> mftEntries, int unitValue, bool catFlag, bool hexdumpFlag)
        {
            bool found = false;
            foreach (var entry in mftEntries)
            {
                if (entry.Length >= 48) 
                {
                    int entryUnitValue = BitConverter.ToInt32(entry, 44);
                    if (entryUnitValue == unitValue)
                    {
                        tableCreation tableInstance = new tableCreation(); //initialize class
                        StringBuilder mftTable = new StringBuilder();

                        //Initialize Variables
                        string fileName = "";
                        string entryTable;
                        int currentOffset = BitConverter.ToInt16(entry, 20);
                        int logicalSize = BitConverter.ToInt32(entry, 24);
                        int fileContentLen = 0;
                        ulong startCluster = 0;
                        ulong endCluster = 0;
                        short dataRunOffset = 0;
                        ulong carveSize = 0;
                        string fileContent = "";
                        bool? resident = null;

                        entryTable = tableInstance.entryHeader(entry);
                        if (catFlag == true) { mftTable.Append(entryTable); }

                        while (currentOffset < logicalSize && currentOffset + 4 < entry.Length) //starts while loop to process all mft entries
                        {
                            int attrType = BitConverter.ToInt32(entry, currentOffset); // sets the attribute type bytes to attrtype as integer 

                            if (attrType == -1)
                                break;

                            string attrTypeName;

                            if (Logic.attrTypeMap.TryGetValue(attrType, out attrTypeName)) // dictionary at top of class 'logic'
                            {
                                //try to extract filename and print for header
                                if (attrTypeName == "$FILE_NAME")
                                {
                                    // Extract the filename
                                    int nameSize = entry[currentOffset + 88];
                                    fileName = Encoding.Unicode.GetString(entry, currentOffset + 90, nameSize * 2);
                                    int parentMFTnumber = BitConverter.ToInt32(entry, currentOffset + 24);
                                }

                                switch (attrTypeName) //switch statement to handle all attributes. Note that this was a recent focus, and some things are old and new
                                {
                                    case "$STANDARD_INFORMATION":
                                        tableInstance.attrHeader(entry, currentOffset, attrTypeName);
                                        string standardInfo = tableInstance.standardInfo(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $STANDARD_INFORMATION\n" + standardInfo + "\n"); }
                                        break;

                                    case "$ATTRIBUTE_LIST":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string attributeList = tableInstance.attrList(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $ATTRIBUTE_LIST\n" + attributeList + "\n"); }
                                        break;

                                    case "$FILE_NAME": //this needs to be here in order to accurately parse the attributes (I think)
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        int nameSize = entry[currentOffset + 88];
                                        fileName = Encoding.Unicode.GetString(entry, currentOffset + 90, nameSize * 2); //needed to define thig again as fileName and fileSize was defined outside of the current scope
                                        string fileNameTable = tableInstance.fileName(entry, currentOffset);
                                        int parentMFTnumber = BitConverter.ToInt32(entry, currentOffset + 24);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $FILE_NAME\n" + fileNameTable + "\n"); }
                                        break;

                                    case "$OBJECT_ID":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string objectID = tableInstance.objectID(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $OBJECT_ID\n" + objectID + "\n"); }
                                        break;

                                    case "$SECURITY_DESCRIPTOR":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string securityDescriptor = tableInstance.securityDescriptor(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $SECURITY_DESCRIPTOR\n" + securityDescriptor + "\n"); }
                                        break;

                                    case "$VOLUME_NAME":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string volumeName = tableInstance.volumeName(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $VOLUME_NAME\n" + volumeName + "\n"); }
                                        break;

                                    case "$VOLUME_INFORMATION":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string volumeInformation = tableInstance.volumeInformation(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $VOLUME_INFORMATION\n" + volumeInformation + "\n"); }
                                        break;

                                    case "$DATA":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string data = tableInstance.data(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $DATA\n" + data + "\n"); }

                                        byte nonResidentFlag = entry[currentOffset + 8]; // The non-resident flag is at offset 8 from the start of the attribute

                                        if (nonResidentFlag == 0) // Resident
                                        {
                                            resident = true;
                                            // For resident attributes, the content size is at offset 16 from the attribute start, and content starts at offset 22
                                            int contentSize = BitConverter.ToInt32(entry, currentOffset + 16);
                                            int contentOffset = currentOffset + 22;
                                            // Ensure reading content does not exceed entry bounds
                                            if (contentOffset + contentSize <= entry.Length) { fileContent = Encoding.ASCII.GetString(entry, contentOffset, contentSize); }
                                            else { Console.WriteLine("Error: Content size exceeds entry bounds."); }
                                        }
                                        else // Non-resident
                                        {
                                            resident = false;
                                            startCluster = BitConverter.ToUInt64(entry, currentOffset + 16);
                                            endCluster = BitConverter.ToUInt64(entry, currentOffset + 24);
                                            dataRunOffset = BitConverter.ToInt16(entry, currentOffset + 32);
                                            carveSize = BitConverter.ToUInt64(entry, currentOffset + 40);
                                        }
                                        break;

                                    case "$INDEX_ROOT":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string indexRoot = tableInstance.indexRoot(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $INDEX_ROOT\n" + indexRoot + "\n"); }
                                        break;

                                    case "$INDEX_ALLOCATION":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string indexAllocation = tableInstance.indexAllocation(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $INDEX_ALLOCATION\n" + indexAllocation + "\n"); }
                                        break;

                                    case "$BITMAP":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string bitmap = tableInstance.bitmap(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $BITMAP\n" + bitmap + "\n"); }
                                        break;

                                    case "$REPARSE_POINT":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string reparsePoint = tableInstance.reparsePoint(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $REPARSE_POINT\n" + reparsePoint + "\n"); }
                                        break;

                                    case "$EA_INFORMATION":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string eaInformation = tableInstance.eaInformation(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $EA_INFORMATION\n" + eaInformation + "\n"); }
                                        break;

                                    case "$EA":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string ea = tableInstance.ea(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $EA\n" + ea + "\n"); }
                                        break;

                                    case "$PROPERTY_SET":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string propertySet = tableInstance.propertySet(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $PROPERTY_SET\n" + propertySet + "\n"); }
                                        break;

                                    case "$LOGGED_UTILITY_STREAM":
                                        tableInstance.attrHeader(entry, 0 + currentOffset, attrTypeName);
                                        string loggedUtilityStream = tableInstance.loggedUtilityStream(entry, currentOffset);
                                        if (catFlag == true) { mftTable.Append("\n Attribute: $LOGGED_UTILITY_STREAM\n" + loggedUtilityStream + "\n"); }
                                        break;
                                }
                            }

                            int attrLength = BitConverter.ToInt32(entry, currentOffset + 4);
                            if (attrLength <= 0) break; // Sanity check
                            currentOffset += attrLength; // Move to next attribute 
                        }

                        if (hexdumpFlag == true)
                        {
                            Console.WriteLine($"      Showing hexdump for MFT Entry: \u001b[32m{fileName}\u001b[0m");
                            Console.WriteLine("+-----------------------------------------------------------------+");
                            Console.WriteLine(BitConverter.ToString(entry).Replace("-", " "));
                        }
                        else if (catFlag == true)
                        {
                            Console.WriteLine($"     Showing MFT Entry for file: \u001b[32m{fileName}\u001b[0m");
                            Console.WriteLine(mftTable);
                        }
                        else if (resident == true && catFlag != true && hexdumpFlag != true)
                        {
                            string directoryPath = Path.Combine(Directory.GetCurrentDirectory(), "carved");
                            if (!Directory.Exists(directoryPath))
                            {
                                Directory.CreateDirectory(directoryPath);
                            }

                            string filePath = Path.Combine(directoryPath, $"{fileName}"); // Adjust the file name as necessary
                            File.WriteAllText(filePath, fileContent);

                            FileInfo fileInfo = new FileInfo(filePath);
                            long fileSize = fileInfo.Length; // File size in bytes

                            DateTime dumpTime = DateTime.Now;

                            Console.WriteLine($"Data was successfully saved to '{filePath}'.");
                            Console.WriteLine($"└────── File Size: \u001b[32m{fileSize} bytes\u001b[0m");
                            Console.WriteLine($"└────── File Dumped At: \u001b[32m{dumpTime}\u001b[0m\n");
                            Console.WriteLine("     Content:\n+---------------------------------------------------+");
                            Console.WriteLine(fileContent);
                        }

                        else if (resident == false && catFlag != true && hexdumpFlag != true)
                        {
                            Console.WriteLine("Note that this file is non-resident and thus can not be carved from the $MFT.\n");
                            Console.WriteLine($"Statistics for \u001b[32m{fileName}\u001b[0m");
                            Console.WriteLine($"└────── Starting Cluster: \u001b[32m{startCluster}\u001b[0m");
                            Console.WriteLine($"└────── Ending Cluster: \u001b[32m{endCluster}\u001b[0m");
                            Console.WriteLine($"└────── Datarun Offset: \u001b[32m{dataRunOffset}\u001b[0m");
                            Console.WriteLine($"└────── File Size to Carve: \u001b[32m{carveSize}\u001b[0m");
                        }
                    }
                }
            }
        }

        static int FindMFTEntryByPath(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, string path)
        {
            path = path.Replace("/", "\\");
            string[] pathComponents = path.Trim('\\').Split('\\');
            int currentEntryNumber = 5;

            foreach (string component in pathComponents)
            {
                bool found = false;
                if (filesystem.ContainsKey(currentEntryNumber))
                {
                    foreach (var item in filesystem[currentEntryNumber])
                    {
                        if (item.extractedName.Equals(component, StringComparison.OrdinalIgnoreCase))
                        {
                            currentEntryNumber = item.entryNumber;
                            found = true;
                            break;
                        }
                    }
                }
                if (!found) { return -1; }
            }

            return currentEntryNumber;
        }



        static int FindMFTEntryByFolderName(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, string folderName)
        {
            foreach (var entry in filesystem)
            {
                foreach (var file in entry.Value)
                {
                    if (file.extractedName.Equals(folderName, StringComparison.OrdinalIgnoreCase)) { return file.entryNumber; }
                }
            }
            return -1; 
        }
        static void FindFilePaths(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, string filename, int entryNumber, string currentPath, HashSet<string> foundPaths)
        {
            if (!filesystem.ContainsKey(entryNumber)) { return; }

            foreach (var item in filesystem[entryNumber])
            {
                string itemPath = currentPath == "" ? item.extractedName : $"/{currentPath}/{item.extractedName}";
                if (item.extractedName.ToLower().Contains(filename.ToLower())) { foundPaths.Add(itemPath); }
                if (filesystem.ContainsKey(item.entryNumber) && !item.extractedName.Equals(".") && !item.extractedName.Equals(".."))
                {
                    FindFilePaths(filesystem, filename, item.entryNumber, itemPath, foundPaths);
                }
            }
        }

        static void DisplayTree(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, int entryNumber, string indent = "", HashSet<string> seenPaths = null, string currentPath = "", bool isRoot = true)
        {
            if (seenPaths == null) seenPaths = new HashSet<string>(); // check to make sure nothing gets double printed (error in dictionary creation, low priority)
            if (isRoot)
            {
                Console.WriteLine(".");
                isRoot = false; // Only the root should be marked as such, subsequent items are not root directory
            }
            if (!filesystem.ContainsKey(entryNumber))
            {
                Console.WriteLine($"{indent}[Folder not found]");
                return;
            }
            var filesAndFolders = filesystem[entryNumber]; // used for tree
            int count = filesAndFolders.Count;
            for (int i = 0; i < count; i++)
            {
                var item = filesAndFolders[i];
                string itemPath = currentPath == "/" ? $"{currentPath}{item.extractedName}" : $"{currentPath}/{item.extractedName}";

                if (!seenPaths.Add(itemPath) || (item.extractedName.Equals(".") && !isRoot)) { continue; } 

                bool isFolder = filesystem.ContainsKey(item.entryNumber);
                if (isFolder)
                {
                    string newIndent = indent + (isRoot ? "" : "|  ");
                    Console.WriteLine($"{indent}{(i < count - 1 ? "|--" : "`--")}{item.extractedName}/  (Entry: \u001b[32m{item.entryNumber}\u001b[0m)");

                    if (!item.extractedName.Equals(".")) { DisplayTree(filesystem, item.entryNumber, newIndent + (i < count - 1 ? "|  " : "   "), seenPaths, itemPath, false); }
                }
                else { Console.WriteLine($"{indent}{(i < count - 1 ? "|--" : "`--")}{item.extractedName}  (Entry: \u001b[32m{item.entryNumber}\u001b[0m)"); }
            }
        }

        public static void RunShell(List<byte[]> mftEntries)
        {
            Console.Write("\n\nWelcome to the MFT Shell. Please pass the command '");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("help");
            Console.ResetColor();
            Console.Write("' for more info. Type '");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("exit");
            Console.ResetColor();
            Console.WriteLine("' to quit.\n");

            var DisplayContents = Logic.DisplayContents; // function in parseAttrs
            var filesystem = Logic.filesystem; // defined in parseAttrs
            bool isRunning = true; // for exit command

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
                bool catflag = false;
                bool hexdumpFlag = false;

                switch (command.ToLower()) //handle all forms of caps lock
                {
                    case "exit":
                        Console.WriteLine("Exiting...");
                        isRunning = false;
                        break;

                    case "help":
                        help(); // help
                        break;

                    case "tree":
                        Console.Write("Command ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(command);
                        Console.ResetColor();
                        Console.Write(" was run on ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(argument + "\n");
                        Console.ResetColor();
                        int rootMFT;
                        if (string.IsNullOrWhiteSpace(argument))
                        {
                            rootMFT = 5; // MFT root
                        }
                        else
                        {
                            rootMFT = FindMFTEntryByFolderName(filesystem, argument); // sets the root dir for tree to be the file passed 
                            if (rootMFT == -1)
                            {
                                Console.WriteLine($"Folder '{argument}' not found.");
                                break;
                            }
                        }
                        DisplayTree(filesystem, rootMFT);
                        break;

                    case "ls": // View contents of directories
                        Console.Write("Command ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(command);
                        Console.ResetColor();
                        Console.Write(" was run on ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(argument + "\n");
                        Console.ResetColor();

                        if (string.IsNullOrWhiteSpace(argument))
                        {
                            DisplayContents(filesystem, 5); // Display root if no argument is given
                        }
                        else
                        {
                            // Normalize the path to use Windows-style separators
                            argument = argument.Replace("/", "\\");

                            // Check if the argument is an absolute path
                            if (argument.StartsWith("\\"))
                            {
                                // Resolve the absolute path to an MFT entry number
                                int mftEntry = FindMFTEntryByPath(filesystem, argument);
                                if (mftEntry == -1)
                                {
                                    Console.WriteLine($"Path '{argument}' not found.");
                                }
                                else
                                {
                                    DisplayContents(filesystem, mftEntry);
                                }
                            }
                            else
                            {
                                // Handle as a direct folder name (existing logic)
                                int mftEntry = FindMFTEntryByFolderName(filesystem, argument);
                                if (mftEntry == -1)
                                {
                                    Console.WriteLine($"Folder '{argument}' not found.");
                                }
                                else
                                {
                                    DisplayContents(filesystem, mftEntry);
                                }
                            }
                        }
                        break;

                    case "find":
                        Console.Write("Command ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(command);
                        Console.ResetColor();
                        Console.Write(" was run on ");
                        Console.ForegroundColor= ConsoleColor.Green;
                        Console.WriteLine(argument + "\n");
                        Console.ResetColor();
                        
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

                    case "cat":
                        catflag = true;
                        Console.Write("Command ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(command);
                        Console.ResetColor();
                        Console.Write(" was run on ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(argument + "\n");
                        Console.ResetColor();
                        if (string.IsNullOrWhiteSpace(argument)) { Console.WriteLine("Please enter an MFT number to view."); }
                        else
                        {
                            if (int.TryParse(argument, out int mftNumber)) { parseMFT(mftEntries, mftNumber, catflag, hexdumpFlag); }
                            else { Console.WriteLine("Invalid MFT number. Please enter a valid number."); }
                        }
                        break;

                    case "carve":
                        Console.Write("Command ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(command);
                        Console.ResetColor();
                        Console.Write(" was run on ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(argument + "\n");
                        Console.ResetColor();
                        if (string.IsNullOrWhiteSpace(argument)) { Console.WriteLine("Please enter an MFT number to view."); }
                        
                        else
                        {
                            if (int.TryParse(argument, out int mftNumber)) { parseMFT(mftEntries, mftNumber, catflag, hexdumpFlag); }
                         
                            else { Console.WriteLine("Invalid MFT number. Please enter a valid number."); }
                        }
                        break;

                    case "hexdump":
                        hexdumpFlag = true;
                        Console.Write("Command ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write(command);
                        Console.ResetColor();
                        Console.Write(" was run on ");
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine(argument + "\n");
                        Console.ResetColor();
                        if (string.IsNullOrWhiteSpace(argument)) { Console.WriteLine("Please enter an MFT number to view."); }
                        else
                        {
                            if (int.TryParse(argument, out int mftNumber)) { parseMFT(mftEntries, mftNumber, catflag, hexdumpFlag); }
                            else { Console.WriteLine("Invalid MFT number. Please enter a valid number."); }
                        }
                        break;


                    case "clear":
                        Console.Clear(); // This will clear the console
                        break;

                    default:
                        if (!string.IsNullOrWhiteSpace(command)) { Console.WriteLine($"Unknown command: {command}"); }
                        break;
                }
            }
        }
    }
}
