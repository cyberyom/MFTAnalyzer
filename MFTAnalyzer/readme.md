```
$ ./MFTAnalyzer.exe-h

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

+------------------------------------+ Help Page +------------------------------------+

Info:
| This tool is meant to gather and parse data from the NTFS file $MTF.
| It is intended to display results of all data in table format,
| offering both readable and raw data.

| To parse an MFT file, simple pass an MFT file to the tool
└───────./MFTAnalyzer.exe C:\path\to\$MFT


Flags:
| -s
└───────./MFTAnalyzer.exe $MFT -s filename
        - Search for a specific file entry based off file name

| -o C:\path\to\output.txt
└───────./MFTAnalyzer.exe $MFT -o output.txt
        - Output the results to a text file

| --csv
└───────./MFTAnalyzer.exe $MFT --csv
        - Output the results to csv format


Additional help:
|Support:
└───────https://github.com/cyberyom/MFTAnalyzer/issues


Version: 0.0.3
Author: CyberYom
https://github.com/cyberyom/MFTAnalyzer
```
