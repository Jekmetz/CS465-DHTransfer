#Imports
import constant as CONST
import os
from os import path
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import hashlib
import string
import random

#Entry point for the program
def main():
	#Init vars
	caID = 0;
	serverID = 0;
	serverPubKey = 0;
	sdhPrivKey = "";
	cdhPrivKey = "";
	hashesMatch = True;
	clientVerify = True;

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
		logln('Client: The certificate is invalid. Connection terminated.');
		return True;

	#simulating connection to port 443
	logln("Client: The connection is complete");

	#diffie-helmans key that both the server and the client have.
	#represented by cdhPrivKey and sdhPrivKey
	(cdhPrivKey,sdhPrivKey) = handshake(serverID);

	#server data transfer
	serverDataTransfer(sdhPrivKey, serverID);

	clientVerify = clientDataTransfer(cdhPrivKey, serverID, serverPubKey);

	if(clientVerify == True):
		print("Success!");
	else:
		print("Failure during client data transfer! Aborting!")

	#Close connection
	logln("Client:The connection is closed.");
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

	with open(CONST.CAFILE[CONST.TESTNUM],'rb') as caF:
		with open(CONST.CAPUBFILE,'rb') as caPubF:
			caPlainText = rsaEncrypt(caF.read(),caPubF.read());

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

	return (caID, serverID, "-----\n" + serverPubKey + "\n-----", caHash == caPlainText[len(caPlainText) - 1]);

#perform the handshake phase
def handshake(serverID):
	cdhPrivKey = 0;
	sdhPrivKey = 0;
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

	#write client public key to file
	with open(CONST.C2SFILE,'w') as f:
		f.write(str(c_x));

	#########SERVER CALCULATIONS################
	#get g and p from DH... we already have them so we will use them.

	s_y = g**b % p;

	logln("Server Hello: {{{}}}:{{{}}}".format(serverID,s_y));

	#write server public key to file
	with open(CONST.S2CFILE,'w') as f:
		f.write(str(s_y));

	#read the client public key
	with open(CONST.C2SFILE,'rb') as f:
		s_x = int(f.read());

	#use key to get dhPrivKey
	sdhPrivKey = s_x**b % p;

	#########CLIENT CALCULATIONS###############

	#read the server public key
	with open(CONST.S2CFILE,'rb') as f:
		c_y = int(f.read());

	cdhPrivKey = c_y**a % p;

	logln("Client: Key-handshake complete Client\nAll future messages will be sent with the generated secret key.");
	logln("Client: Client ready to enter the Data Transfer phase.");

	##########SERVER CALCULATIONS##############
	logln("Server: Key-handshake complete Server\nAll future messages will be sent with the generated secret key.");
	logln("Server: Server ready to enter the Data Transfer phase.");

	return str(cdhPrivKey)[0:32],str(sdhPrivKey)[0:32];

def serverDataTransfer(sdhPrivKey, serverID):
	data = "";
	signature = "";
	h = 0;

	#get all of the digits and characters from the datfile!
	with (open(CONST.DATFILE,'rb')) as f:
		data = ''.join(filter(lambda c: c.isalpha() or c.isdigit(),f.read()));

	#calculate sha256 hash and tack that on to the data at the end
	h = hashlib.sha256(data).hexdigest();
	data += '\n' + str(h);

	#sign file with private key
	with open(CONST.SPRIVFILE,'rb') as sPrivF:
		signature = rsaDecrypt(serverID,sPrivF.read());

	data += '\n' + signature;

	cipher = AES.new(sdhPrivKey, AES.MODE_ECB);

	#Add appropriate padding at the beginning
	data = '\0'*(AES.block_size - (len(data) % AES.block_size)) + data;

	data = cipher.encrypt(data);

	logln("Server: The file has been encrypted.");

	with open(CONST.SECRETFILE,'w') as f:
		f.write(data);

	return;

def clientDataTransfer(cdhPrivKey, serverID, serverPubKey):
	#Init Vars
	data = "";
	fServerID = "";
	fdata = "";
	fhash = "";


	with open(CONST.SECRETFILE, 'rb') as f:
		data = f.read();

	#decrypt with AES
	cipher = AES.new(cdhPrivKey, AES.MODE_ECB);
	data = cipher.decrypt(data).split('\n');

	#get all of the parts
	#remove padding
	fdata = ''.join(filter(lambda c: c in string.printable,data[0]));
	fhash = data[1];
	fServerID = data[2];

	#verify that it came from the server by using the server RSA pubkey
	#catch to make sure the RSA pubkey is correct
	try:
		fServerID = rsaEncrypt(fServerID,serverPubKey);
	except Exception:
		logln("Client: Bad RSA public key from initial file!");
		return False;
		
	if(fServerID != serverID):
		logln("Client: ServerID was not signed properly!");
		return False;
	#we know the file was signed correctly

	#calculate the hash of the data
	if (fhash != str(hashlib.sha256(fdata).hexdigest())):
		logln("Client: The file has been tampered with");
		return False;
	
	#we know the data was not tampered with
	print("Data:\n" + fdata);
	logln('Client:\nDATA:\n\n{}\n'.format(fdata));
	return True;


#Encrypt given data with a given RSA Public Key text
def rsaEncrypt(plainText,pubRsa):
	rsaKey = 0;
	ciphertext = 0;
	
	#get RSA key 
	rsaKey = RSA.importKey(pubRsa);

	#generate ciphertext
	ciphertext = rsaKey.encrypt(plainText,0);

	#return ciphertext
	return ciphertext[0];

#Decrypt given data with a given RSA text
def rsaDecrypt(ciphertext, privRsa):
	rsaKey = 0;
	plaintext = 0;

	#get RSA key
	rsaKey = RSA.importKey(privRsa);

	#generate plaintext
	plaintext = rsaKey.decrypt(ciphertext);

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
