
// This is a refactor for MFTAnalyzer by CyberYom
// MFTAnalyzer was origonally written in Python, and is currently being refactored in C#
// This project lives in Github

using System;
using System.IO;
using System.Collections.Concurrent;
using System.ComponentModel.Design;
using System.Text;
using System.Threading.Channels;

namespace MFTAnalyzer
{
    class Logic
    {
        static readonly byte[] targetBytes = { 0x46, 0x49, 0x4C, 0x45 }; // FILE header

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

                byte[] mftEntry = new byte[logicalSize];
                Array.Copy(fileBytes, offset, mftEntry, 0, logicalSize);
                startSearchOffset = offset + logicalSize;            }
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
