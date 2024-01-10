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
