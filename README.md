# AES Scan Chain Analysis Attack

 ## 1.Description
 
This is a program for performing a scan chain attack on a unique AES core to recover the original encryption key embedded in the binary code.
	
 ### How It Performs the Attack
 
This implementation is based on the algorithms described in papers like “Secure Scan: A Design-for-Test Architecture for Crypto Chips”, Bo Yang et. al., IEEE TCAD 2006. 
	
The 128-bit AES core encrypts 128-bit data blocks using 128-bit secret key. The first step of this scan chain attack is to determine the scan chain structure/layout. As one byte change at input will result in 32 flip-flop changes in data register R, we can use input with one 
byte difference to compare and figure out the correspondences between the scan chain bits and the register R bits after enough input patterns.
	
In this way, we can finally determine the every bit position of the input register and the data register in the scan chain.
	
The second step of this attack is to find all the candidate RK0 bytes by changing one plaintext byte(2t and 2k+1) to compare the differences in register R using f1^f2.
	
Finally, we test all the candidate keys by comparing the encryption ciphertext to determine the final secret key.

 ## 2.Getting Started
 
 ### Environment and Tools
 
* System: Windows 11 Home 64-bit
* Language: Python 3.9.13
* Libraries: 
	cryptography==37.0.1
	openpyxl==3.0.10
		
 ### How To Use the Program
 
To run this program, we first need to install python environment by visiting the python website: https://www.python.org/downloads/windows/
	
Then we can install all the requirements by running the following command with the provided requirements.txt in the current folder:
	
```
pip install -r requirements.txt
```
	
After this, we can use any python platform to run the main.py code or using the following command in the Codes folder:
	
```
python main.py
```
 ### Check the Results

After running the code, we can both see the output of input/data register indices corresponding to the scan chain bit positions in the terminal and the output.txt file in the same folder as main.py. 

Also, the scan chain bit-purpose table will be printed in scan_sheet.xlsx in the same table. You can check these files to follow all the results.
	
 ## 3.Author
 
Songsen Wang netID: sw5822
 
 