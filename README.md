# MFTAnalyzer
```
> MFTAnalyzer.exe

        M   M  FFFFF  TTTTT
        MM MM  F        T
        M M M  FFF      T
        M   M  F        T
        M   M  F        T

AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ   EEEE   RRRR
A   A  NN  N  A   A  L      Y Y      Z    E      R   R
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR
A   A  N  NN  A   A  L       Y     Z      E      R R
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR
             by CyberYom

| Version: 1.0.0
| https://github.com/cyberyom/MFTAnalyzer
└---------------------------------------------------------------------------

Welcome to MFT Analyzer. This tool is designed to parse and display MFT metadata.
Passing -h will display a help menu.
```
MFTAnalyzer is a powerful tool designed for parsing and displaying metadata relevant to an MFT file. With a new C# refactor, MFTAnalyzer is faster than ever, beating out many other tools when working with large-scale MFT files. 
 
 
## Features

- **Feature 1:** By simply passing the tool an MFT file, it will generate tables for all relevant data from each and every MFT entry found. 
- **Feature 2:** By passing the <-sn> flag, one will be able to search for specific file entries, using the file name as the search term.
- **Feature 3:** By passing the <-sm> flag, one will be able to search for specific file entries, using the file entry number as the search term.   
- **Feature 4:** Tool is able to recreate file structure of whole disk, or specific folders, as well as give you a shell in the filesystem, with limited commands. 
- **Feature 5:** Tool is capable of carving files in the MFT. For resident files, it just pulls the data from the MFT. For non-resident files, it will return relevant information to carve the file.
 
### Prerequisites

Before you begin, ensure you have met the following requirements:
- Requirement 1: Make sure that the $MFT file you are analyzing is from an NTFS version 3 + system. Tool is incompatiable with < NTFS 3.0
- Requirement 2: You are on a 64 bit system
 
 
### First Run
Passing -h to the tool will display a help page, showing each command that is available.
```
>MFTAnalyzer.exe -h

        M   M  FFFFF  TTTTT
        MM MM  F        T
        M M M  FFF      T
        M   M  F        T
        M   M  F        T

AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ   EEEE   RRRR
A   A  NN  N  A   A  L      Y Y      Z    E      R   R
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR
A   A  N  NN  A   A  L       Y     Z      E      R R
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR
             by CyberYom

| Version: 1.0.0
| https://github.com/cyberyom/MFTAnalyzer
└---------------------------------------------------------------------------


+------------------------------------+ Help Page +------------------------------------+

Info:
| This tool is meant to gather and parse data from the NTFS file $MTF.
| It is intended to display results of all data in table format,
| offering both readable and raw data.

| To parse an MFT file, simply pass an MFT file to the tool
└───────./MFTAnalyzer.exe C:\path\to\$MFT


Flags:
| -sn
└───────./MFTAnalyzer.exe $MFT -sn filename
        - Search for a specific file entry based off file name

| -sm
└───────./MFTAnalyzer.exe $MFT -sm ENTRYNUMBER
        - Search for a specific file entry based off MFT file entry number

| --shell
└───────./MFTAnalyzer.exe $MFT --shell
        - Enter a shell with the MFT file


| -o
└───────./MFTAnalyzer.exe $MFT -sn filename -o
        - Output to a text file

Additional help:
|Support:
└───────https://github.com/cyberyom/MFTAnalyzer/issues


Version: 1.0.0
Author: CyberYom
https://github.com/cyberyom/MFTAnalyzer
```

### Shell Mode

This tool has the ability to rebuild the entire filesystem of the system from which the MFT was extracted from. Upon running with the --shell command, a shell is opened up, with the filesystem in memory.
This allows us to run various commands against the filesystem. Pass the command 'help' to view all the commands in this mode
```
Welcome to the MFT Shell. Please pass the command 'help' for more info. Type 'exit' to quit.

MFT Shell > help

     Available Commands:
+-----------------------------------------------------------------+
help
└────── Display the help menu

tree
└────── Recursively display the file structure of directory passed. Used with filenames.

ls
└────── View the contents of a Directory. Used with file names

find
└────── Find MFT entry for specific file. Used with file names

cat
└────── View MFT entry for file. Used with MFT numbers

carve
└────── Carve the contents of resident files, return offsets needed to carve fir non-resident files. Used with MFT numbers.

hexdump
└────── View raw data for each MFT entry. Used with MFT numbers

clear
└────── Clear the screen

exit
└────── Exit the shell

```

More documentation will be provided soon in the wiki...

## Special Thanks
The development of this project would not be possible without the help of the following individuals. Their contributions are greatly appreciated.
- Ali Hadi, Champlain College.
- Solomon Ince, Freelance.
- Amy Keigwin, Champlain College
- Sam Guinther, The Leahy Center
- Joachim Metz, Google, [Documentation](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc)



