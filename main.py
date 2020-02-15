#Imports
import constant as CONST
import os
from os import path
from Crypto.PublicKey import RSA
import hashlib
import string
import random

#Entry point for the program
def main():
	#Init vars
	caID = 0;
	serverID = 0;
	serverPubKey = 0;
	dhPrivKey = 0;
	hashesMatch = True;

	#init random number generator
	random.seed();

	#Validate that all the files exist
	if(not validateFilesExist()):
		print("Aborting!");
		return False;
	#Get all of the information from CA.txt
	#using the CA-RSA-Public key from CA-PublicKey.txt
	(caID, serverID, serverPubKey, hashesMatch) = getCAInfo();

	if(not hashesMatch):
		print('The certificate is invalid. Connection terminated.');

	#simulating connection to port 443
	logln("Client: The connection is complete");

	#diffie-helmans key that both the server and the client have. We will only use this instance.
	dhPrivKey = handshake(serverID);

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

#perform the handshake phase
def handshake(serverID):
	dhPrivKey = 0;
	p = 0;	#mod p
	g = 0;  #base g
	a = random.randint(1,10**4);  #client private key
	b = random.randint(1,10**4);  #server private key
	c_x = 0;  #client generated public key
	s_x = 0;  #server recieved client public key
	c_y = 0;  #client recieved server public key
	s_y = 0;  #server generated public key

	logln("Client Hello: TLS version 1.3: TLS_AES_256_GCM_SHA384,TLS_CHACHA202_POLY1305_SHA256,TLS_AES_128_GCM_SHA256");

	#########CLIENT CALCULATIONS################
	with open(CONST.DHFILE,'rb') as f:
		gp = f.read().split("\n");
		g = int(gp[0][1:len(gp[0]) - 2]); #get g by stripping off the {}
		p = int(gp[1][1:len(gp[1]) - 1]); #get p by stripping off the []

	c_x = g**a % p;

	logln("Client: Generated x - " + str(c_x));

	#write client public key to file
	with open(CONST.C2SFILE,'w') as f:
		f.write(str(c_x));

	#########SERVER CALCULATIONS################
	#get g and p from DH... we already have them so we will use them.

	s_y = g**b % p;

	logln("Server: Generated y - " + str(s_y));

	#write server public key to file
	with open(CONST.S2CFILE,'w') as f:
		f.write(str(s_y));

	#read the client public key
	with open(CONST.C2SFILE,'rb') as f:
		s_x = int(f.read());

	#use key to get dhPrivKey
	dhPrivKey = s_x**b % p;

	logln("Server: Generated secret key - " + str(dhPrivKey));

	#########CLIENT CALCULATIONS###############

	#read the server public key
	with open(CONST.S2CFILE,'rb') as f:
		c_y = int(f.read());

	dhPrivKey = c_y**a % p;

	logln("Client: Generated secret key - " + str(dhPrivKey));

	return dhPrivKey;

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

	#at the end, delete the old output files if they exists
	if(path.exists(CONST.LOGFILE)):
		os.remove(CONST.LOGFILE);
	if(path.exists(CONST.C2SFILE)):
		os.remove(CONST.C2SFILE);
	if(path.exists(CONST.S2CFILE)):
		os.remove(CONST.S2CFILE);

	return ret;

#Sets entry point for the program to run main()
if __name__ == "__main__":
	main()
