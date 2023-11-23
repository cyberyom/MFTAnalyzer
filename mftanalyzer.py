"""
Program written by CyberYom
Written in Python 3.11.6

This program is meant to take a MFT file as input, and parse the MFT file, displaying all the information contained
in the MFT file entry such as x-ways templates will.

Program lives on github.
""" 
import sys
import os

print("\033[91m" + """
		M   M  FFFFF  TTTTT  
		MM MM  F        T    
		M M M  FFF      T    
		M   M  F        T    
		M   M  F        T    
""" + "\033[92m" + """
AAAAA  N   N  AAAAA  L     Y   Y  ZZZZZ  EEEEE  RRRR  
A   A  NN  N  A   A  L      Y Y      Z    E      R   R 
AAAAA  N N N  AAAAA  L       Y      Z     EEEE   RRRR  
A   A  N  NN  A   A  L       Y     Z      E      R R   
A   A  N   N  A   A  LLLLL   Y     ZZZZZ  EEEEE  R  RR 
""" + "\033[0m" + "	by CyberYom\n\n")


def firstrun():
	print('Welcome to MFT Analyzer. This tool is designed to parse and display MFT metadata. Passing -h will display a help menu.' + '\n\n')

def help():
	print("This tool has a few options available. \n")
	print("For simply parsing an MFT file, pass the location of the MFT file.\n-----./MFTAnalyzer.py C:\Path\To\MFTfile-----\n")
	print("To export your results, use the -o flag.\n-----./MFTAnalyzer.py C:\Path\To\MFTfile -o C:\Desired\Path\To\Results-----\n")
	print("To export your results to a CSV, pass the -csv flag (with the -o flag).\n-----./MFTAnalyzer.py C:\Path\To\MFT -csv -o C:\Desired\Path\To\Results.csv-----\n")

def handle_path(providedpath):
    if os.path.exists(providedpath):
        # Return or process the path and return the result
        return 'Path exists and data processed.'
    else:
        return 'File not found.'

def output_results(data, outputpath):
    with open(outputpath, 'w') as file:
        file.write(data)
    print(f'Output written to file {outputpath}')

# ... (initial argument handling remains the same)

if len(sys.argv) == 1:
    firstrun()
elif '-h' in sys.argv:
    help()
else:
    argpath = sys.argv[1]
    path_output = handle_path(argpath)
    print(path_output)  # Add this line to print the output to the screen

    if '-o' in sys.argv:
        try:
            o_index = sys.argv.index('-o')
            if o_index + 1 < len(sys.argv):
                output_path = sys.argv[o_index + 1]
                output_results(path_output, output_path)
            else:
                print("No output path provided after -o.")
        except ValueError:
            print("Error processing -o argument.")