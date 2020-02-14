#Imports
import constant as CONST
import os
from os import path
from Crypto.PublicKey import RSA
import hashlib
import string

#Entry point for the program
def main():
	#Init vars
	caID = 0;
	serverID = 0;
	serverPubKey = 0;
	hashesMatch = True;

	#Validate that all the files exist
	if(not validateFilesExist()):
		print("Aborting!");
		return False;
	#Get all of the information from CA.txt
	#using the CA-RSA-Public key from CA-PublicKey.txt
	(caID, serverID, serverPubKey, hashesMatch) = getCAInfo();

	if(not hashesMatch):
		print('The certificate is invalid. Connection terminated.');

	print("Success!");
	return True;
	
#Gets all of the information from the correct CA*.txt
#by decrypting with RSA from CA-PublicKey.txt
def getCAInfo():
	#Init Vars
	caID = '';
	serverID = '';
	serverPubKey = '';
	hashesMatch = True;
	caPlainText = "";

	caPlainText = rsaEncrypt(CONST.CAFILE[CONST.TESTNUM],CONST.CAPUBFILE);

	caPlainText = caPlainText.split('\n');

	#calculate caID by joining together only the printable characters from the caID
	caID = makePrintable(caPlainText[0]);
	serverID = caPlainText[1];

	#calculate serverPubKey by joining together all of the rest minus the hash with a \n
	serverPubKey = '\n'.join(caPlainText[2:len(caPlainText) - 1]);

	#Hash everything with a newline at the end
	caHash = hashlib.sha256('\n'.join([caID,serverID,serverPubKey]) + '\n').hexdigest();

	logln("Client: caID = " + caID);
	logln("Client: serverID = " + serverID);
	logln("Client: serverPubKey = " + serverPubKey);
	logln("Client: hash provided = " + caPlainText[len(caPlainText) - 1]);
	logln("Client: hash calculated = " + caHash);

	return (caID, serverID, serverPubKey, caHash == caPlainText[len(caPlainText) - 1]);

#Encrypt a given file (plainTextFileName) with a given RSA Public Key (pubRsaFileName)
def rsaEncrypt(plainTextFileName,pubRsaFileName):
	rsaKey = 0;
	ciphertext = 0;
	
	#get RSA key from file
	with open(pubRsaFileName,'rb') as f:
		rsaKey = RSA.importKey(f.read());

	#generate ciphertext
	with open(plainTextFileName,'rb') as f:
		ciphertext = rsaKey.encrypt(f.read(),0);

	#return ciphertext
	return ciphertext[0];

#Decrypt a given file (ciphertextFileName) with a given RSA private key privRsaFileeName
def rsaDecrypt(ciphertextFileName, privRsaFileName):
	rsaKey = 0;
	plaintext = 0;

	#get RSA key from file
	with open(privRsaFileName,'rb') as f:
		rsaKey = RSA.importKey(f.read());

	#generate plaintext
	with open(ciphertextFileName,'rb') as f:
		plaintext = rsaKey.decrypt(f.read());

	return plaintext;

#log a string to the log file
def logln(s):
	with open(CONST.LOGFILE,'a') as f:
		f.write(s + '\n');

#removes non printable characters from a string
def makePrintable(s):
	return ''.join(filter(lambda c: c in string.printable,s));

#Checks to make sure all of the necessary inputs exist!
def validateFilesExist():
	ret = True; #Assume we have everything... get proven otherwise
	if (not path.exists(CONST.CAFILE[CONST.TESTNUM])):
		print("No CA File!");
		ret = False;
	if(not path.exists(CONST.CAPUBFILE)):
		print("No CA Public Key File!");
		ret = False;
	if(not path.exists(CONST.SPRIVFILE)):
		print("No Server Private Key File!");
		ret = False;
	if(not path.exists(CONST.SPUBFILE)):
		print("No Server Public Key File!");
		ret = False;
	if(not path.exists(CONST.DHFILE)):
		print("No Diffie-Helmans p,g File!");
		ret = False;
	if(not path.exists(CONST.DATFILE)):
		print("No Data File!");
		ret = False;

	#at the end, delete the old log file if it exists
	if(path.exists(CONST.LOGFILE)):
		os.remove(CONST.LOGFILE);
	return ret;

#Sets entry point for the program to run main()
if __name__ == "__main__":
	main()
