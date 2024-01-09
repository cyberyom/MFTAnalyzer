# MFTAnalyzer
```
        M   M  FFFFF  TTTTT
        MM MM  F        T
        M M M  FFF      T
        M   M  F        T
        M   M  F        T
AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ  EEEEE  RRRRR
A   A  NN  N  A   A  L      Y Y      Z    E      R   R
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR
A   A  N  NN  A   A  L       Y     Z      E      R R
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR
      by CyberYom
```
MFTAnalyzer is a powerful tool designed for parsing and displaying metadata relavant to an MFT file. It also has the abilities to directly work with disk images for various tasks such as file carving and more. It's built with python 3.11.6 and is perfect for analyzing MFT files, as well as using MFT information to do other actions. 
 
 
## Features

- **Feature 1:** By simply passing the tool an MFT file, it will generate tables for all relavant data from each and every MFT entry found. (COMPLETE)
- **Feature 2:** By passing the <-s> flag, one will be able to search for specific file entries, using the file name as the search term. (COMPLETE) 
- **Feature 3:** Tool is able to recreate file structure of whole disk, or specific folders. (NOT STARTED)
- **Feature 4:** Tool is capable of carving files in the MFT. For resident files, it just pulls the data from the MFT. For non-resident files, it will need to have a disk image passed, so the file can be carved. (NOT STARTED)
- **Feature 5:** This tool has multiple options for exporting results. Currently, you can export tables to a txt file, or export results to a CSV file. (IN DEVELOPMENT)
- **More to come...**
 
 
 
 
## Getting Started
```
 $ .\MFTAnalyzer.exe -h

        M   M  FFFFF  TTTTT
        MM MM  F        T
        M M M  FFF      T
        M   M  F        T
        M   M  F        T

AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ  EEEEE  RRRRR
A   A  NN  N  A   A  L      Y Y      Z    E      R   R
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR
A   A  N  NN  A   A  L       Y     Z      E      R R
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR
      by CyberYom


This tool has a few options available.

For simply parsing an MFT file, pass the location of the MFT file.
-----./MFTAnalyzer.exe C:\Path\To\MFTfile-----

To search for specific file entries, pass the -s flag, along with the string to search for.
-----./MFTAnalyzer.exe C:\Path\To\MFT -s testfile -----

To export your results, use the -o flag.
-----./MFTAnalyzer.exe C:\Path\To\MFTfile -o C:\Desired\Path\To\Results.txt-----

To export your results to a CSV, pass the --csv flag.
-----./MFTAnalyzer.exe C:\Path\To\MFT --csv -----

```
### Prerequisites

Before you begin, ensure you have met the following requirements:
- Requirement 1: Make sure that the $MFT file you are analyzing is from an NTFS version 3 + system. Tool is incompatiable with < NTFS 3.0
- Requirement 2: You are on a 64 bit system
- Requirement 3: If you are running from source code, you will need the python module Pretty Table installed. 
 
 
### Installation

To install MFTAnalyzer, follow these steps:
#### From Source
1) Pull the repo down
2) Install pyinstaller (tool used for compilation of python scripts)
```
$ python -m pip install pyinstaller
```
3) Compile program
```
$ pyinstaller MFTAnalyzer.py --onefile
```
4) Done!

#### From Github
1) Navigate to [here](https://github.com/cyberyom/MFTAnalyzer/releases)
2) Download the compiled copy for your OS. Note that currently, only 64 bit systems are supported
3) Navigate to file and done!
 
 
### First Run
Upon simply running the tool by itself, without passing any flags, you will get a simple about screen. 
```
$ .\MFTAnalyzer.exe

        M   M  FFFFF  TTTTT
        MM MM  F        T
        M M M  FFF      T
        M   M  F        T
        M   M  F        T

AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ  EEEEE  RRRRR
A   A  NN  N  A   A  L      Y Y      Z    E      R   R
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR
A   A  N  NN  A   A  L       Y     Z      E      R R
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR
      by CyberYom


Welcome to MFT Analyzer. This tool is designed to parse and display MFT metadata.
Passing -h will display a help menu.
```
Passing -h will show you all of the options available to you. Note, the first argument you pass should be the **absolute path** to the target MFT file. 
 
 
 
 
## Special Thanks
The development of this project would not be possible without the help of the following individuals. Their contributions are greatly appreciated.
- Ali Hadi, Champlain College.
- Solomon Ince, Freelance.
- Amy Keigwin, Champlain College
- Sam Guinther, The Leahy Center
- Joachim Metz, Google, [Documentation](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc)



