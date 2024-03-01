using System;

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
                string itemPath = currentPath == "" ? item.extractedName : $"/{currentPath}/{item.extractedName}";

                if (item.extractedName.Equals(filename, StringComparison.OrdinalIgnoreCase))
                {
                    foundPaths.Add(itemPath); // Add the path to the set of found paths
                }

                if (filesystem.ContainsKey(item.entryNumber) && !item.extractedName.Equals(".") && !item.extractedName.Equals(".."))
                {
                    FindFilePaths(filesystem, filename, item.entryNumber, itemPath, foundPaths);
                }
            }
        }
        public static void DisplayTree(Dictionary<int, List<(string extractedName, int entryNumber)>> filesystem, int entryNumber, string indent = "", HashSet<string> seenPaths = null, string currentPath = "", bool isRoot = true)
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

                if (!seenPaths.Add(itemPath) || (item.extractedName.Equals(".") && !isRoot))
                {
                    continue; // Skip if already processed or if it's the root directory being processed again
                }

                bool isFolder = filesystem.ContainsKey(item.entryNumber);
                if (isFolder)
                {
                    string newIndent = indent + (isRoot ? "" : "|  ");
                    Console.WriteLine($"{indent}{(i < count - 1 ? "|--" : "`--")}{item.extractedName}/");

                    if (!item.extractedName.Equals("."))
                    {
                        DisplayTree(filesystem, item.entryNumber, newIndent + (i < count - 1 ? "|  " : "   "), seenPaths, itemPath, false);
                    }
                }
                else
                {
                    Console.WriteLine($"{indent}{(i < count - 1 ? "|--" : "`--")}{item.extractedName}");
                }
            }
        }

        public static void RunShell()
        {
            Console.Write("\nWelcome to the MFT Shell. Please pass the command '");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("help");
            Console.ResetColor();
            Console.Write("' for more info. Type '");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.Write("exit");
            Console.ResetColor();
            Console.WriteLine("'to quit.\n");

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

                    case "ls": // view contents of directories
                        int mftFolder;
                        if (string.IsNullOrWhiteSpace(argument))
                        {
                            mftFolder = 5;
                        }
                        else
                        {
                            mftFolder = FindMFTEntryByFolderName(filesystem, argument); 
                            if (mftFolder == -1)
                            {
                                Console.WriteLine($"Folder '{argument}' not found.");
                                break;
                            }
                        }
                        DisplayContents(filesystem, mftFolder);
                        break;

                    // find files
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
    }
}
