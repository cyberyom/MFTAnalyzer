# MFTAnalyzer

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

MFTAnalyzer is a powerful tool designed for parsing and displaying metadata relavant to an MFT file. It also has the abilities to directly work with disk images for various tasks such as file carving and more. It's built with python 3.11.6 and is perfect for analyzing MFT files, as well as using MFT information to do other actions. 

## Features

- **Feature 1:** By simply passing the tool an MFT file, it will generate tables for all relavant data from each and every MFT entry found. (COMPLETE)
- **Feature 2:** By passing the <-s> flag, one will be able to search for specific file entries, using the file name as the search term. (COMPLETE) 
- **Feature 3:** Tool is able to recreate file structure of whole disk, or specific folders. (NOT STARTED)
- **Feature 4:** Tool is capable of carving files in the MFT. For resident files, it just pulls the data from the MFT. For non-resident files, it will need to have a disk image passed, so the file can be carved. (NOT STARTED)
- **Feature 5:** This tool has multiple options for exporting results. Currently, you can export tables to a txt file, or export results to a CSV file. (IN DEVELOPMENT)
- **More to come...**

## Getting Started

### Prerequisites

Before you begin, ensure you have met the following requirements:
- Requirement 1: Make sure that the $MFT file you are analyzing is from an NTFS version 3 + system. Tool is incompatiable with < NTFS 3.0
- Requirement 2: You are on a 64 bit system

### Installation

To install MFTAnalyzer, follow these steps:


