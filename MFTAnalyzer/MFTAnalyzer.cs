
// This is a refactor for MFTAnalyzer by CyberYom
// MFTAnalyzer was origonally written in Python, and is currently being refactored in C#
// This project lives in Github

using System;
using System.Linq;
using System.IO;
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
    public class Execution
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
AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ   EEEE   RRRR  
A   A  NN  N  A   A  L      Y Y      Z    E      R   R 
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR  
A   A  N  NN  A   A  L       Y     Z      E      R R   
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR 
");
            Console.ResetColor();
            Console.WriteLine("             by CyberYom\n");
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
            Console.WriteLine("| -o \n└───────./MFTAnalyzer.exe $MFT -sn filename -o\n\t- Output to a text file\n");
            Console.WriteLine("Additional help:\n|Support:\n└───────https://github.com/cyberyom/MFTAnalyzer/issues\n\n");
            Console.WriteLine("Version: 1.0.0");
            Console.WriteLine("Author: CyberYom");
            Console.WriteLine("https://github.com/cyberyom/MFTAnalyzer");
        }

        public static void Main(string[] args)
        {
            asciiArt();
            string filePath = args.Length > 0 ? args[0] : null;
            string fullPath = filePath != null ? Path.GetFullPath(filePath) : null;
            bool shellArgumentPresent = args.Contains("--shell");
            string subdirectoryName = "extractions";
            string outputPath = "MFTAnalyzerOutput.txt"; // Default output file name
            string currentDirectory = Directory.GetCurrentDirectory();
            string extractionDirectoryPath = Path.Combine(currentDirectory, subdirectoryName);
            if (!Directory.Exists(extractionDirectoryPath))
            {
                Directory.CreateDirectory(extractionDirectoryPath);
            }
            string fullOutputPath = Path.Combine(extractionDirectoryPath, outputPath);

            try
            {
                using (var fileStream = new FileStream(fullOutputPath, FileMode.Create, FileAccess.Write))
                using (var streamWriter = new StreamWriter(fileStream))
                using (var doubleWriter = new DoubleWriter(Console.Out, streamWriter))
                {
                    Console.SetOut(doubleWriter);
                    if (args.Length == 1 && args[0] == "-h") { help(); }
                    else if (shellArgumentPresent) { ProcessShellArgument(fullPath); }
                    else { ProcessFlags(args, fullPath); } // Handle other arguments, not added yet tho

                }
            }
            finally
            {
                Console.SetOut(new StreamWriter(Console.OpenStandardOutput()) { AutoFlush = true });
            }

        }

        static void ProcessShellArgument(string fullPath)
        {
            Console.WriteLine("| Version: 1.0.0\n| https://github.com/cyberyom/MFTAnalyzer\n└---------------------------------------------------------------------------\n");
            if (fullPath != null)
            {
                WarnIfLargeFile(fullPath);
                var mftEntries = Logic.extractMFT(fullPath, null, -1, true);
                Shell.RunShell(mftEntries);
            }
        }

        static void ProcessFlags(string[] args, string fullPath)
        {
            bool searchName = Array.IndexOf(args, "-sn") != -1;
            bool searchMFT = Array.IndexOf(args, "-sm") != -1;
            string filename = null;
            int mftNumber = -1;

            if (searchName)
            {
                int index = Array.IndexOf(args, "-sn");
                if (index + 1 < args.Length)
                {
                    filename = args[index + 1];
                }
            }

            if (searchMFT)
            {
                int index = Array.IndexOf(args, "-sm");
                if (index + 1 < args.Length && int.TryParse(args[index + 1], out int num))
                {
                    mftNumber = num;
                }
            }

            if (fullPath != null && !args.Contains("--shell"))
            {
                WarnIfLargeFile(fullPath); // Warn if the file is large, applicable for non-shell operations too
                Logic.extractMFT(fullPath, filename, mftNumber, false); // Pass filename and adjust method signature accordingly
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
                Console.WriteLine(" bytes). Command may take some time.\n");
            }
        }
    }
}
