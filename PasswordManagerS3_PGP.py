# 2018-02-08 SK upgrade to PGP standard (Need public and encrypted private keys in same folder (.asc files))
# 2017-11-06 SK Encrypted password manager - s3 version
import datetime
import re
import os
import math
import boto3
import getpass
import pgpy
import warnings
import pyperclip
import configparser

warnings.filterwarnings("ignore")


#source: https://pgpy.readthedocs.io/en/latest/examples.html
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from sys import platform

#probably not needed anymore
#https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
import hashlib,re

main_config = configparser.ConfigParser(allow_no_value = True)

main_config.read('config.ini')



#Custom Private Information -- DO NOT SHARE -- START
# master password is used to decrypt individual password entry lines, along with secret_key from below
master_pwd = None
aws_access_key = main_config['SETTINGS']['AWS_ACCESS_KEY']
aws_secret_key = main_config['SETTINGS']['AWS_ACCESS_PW']
BUCKET = main_config['SETTINGS']['BUCKET']

# convert a string to bytes: ref: https://stackoverflow.com/questions/7585435/best-way-to-convert-string-to-bytes-in-python-3
# to convert a byte string to string: ref: # ref: https://stackoverflow.com/questions/606191/convert-bytes-to-a-string
aws_access_key_as_bytes = str.encode(aws_access_key)
# below 16-byte secret key is derived from aws access key, and is used to encrypt the password lines
secret_key = aws_access_key_as_bytes[:16] 

#AWS Bucket where to store the password file - make sure it is created 
#BUCKET = 'aplan'

#secret_key = os.urandom(32) 

#exported public key file (from cleopatra by GNUPGP program) with .asc extension
PUBLIC_KEY_ASC_FILE=main_config['SETTINGS']['PUBLIC_KEY_ASC_FILE']

#exported pass phrase protected private key file (from cleopatra by GNUPGP program) with .asc extension
PRIVATE_KEY_ASC_FILE=main_config['SETTINGS']['PRIVATE_KEY_ASC_FILE']

#load the public & private key files
# A key can be loaded from a file, like so:
# look up using "underscore" as "don't care" variable

receiver_public_key, _ = pgpy.PGPKey.from_file(PUBLIC_KEY_ASC_FILE)
# encrypted private key using pass phrase. Need to unlock to use for decryption
receiver_private_key, _ = pgpy.PGPKey.from_file(PRIVATE_KEY_ASC_FILE)
#prompt user for this , from his memory. the 1-password
receiver_private_key_pass_phrase = ''
#Custom Private Information -- DO NOT SHARE -- END

#encrypt and decrypt class
class pgp_encrypt_decrypt:
        

    def generate_pgp_message(self, plain_text_msg):
        # this creates a standard message from text
        # it will also be compressed, by default with ZIP DEFLATE, unless otherwise specified
        pgp_msg = pgpy.PGPMessage.new(plain_text_msg)
        return pgp_msg

    def generate_pgp_message_for_file(self, plain_text_msg):
        # this creates a standard message from text
        # it will also be compressed, by default with ZIP DEFLATE, unless otherwise specified
        pgp_msg = pgpy.PGPMessage.new(plain_text_msg, file=True)
        return pgp_msg

    def print_pgp_message_in_plain_text(self, pgp_msg):
        # plain text of the PGP message
        return pgp_msg.message

    def encrypt_file(self, unencrypted_text):
        # The symmetric cipher should be specified, in case the first preferred cipher is not
        #  the same for all recipients' public keys
        cipher = pgpy.constants.SymmetricKeyAlgorithm.AES256
        sessionkey = cipher.gen_key()

        #convert plain text to PGP message
        pgp_msg = self.generate_pgp_message_for_file(unencrypted_text)

        # encrypt the message to multiple recipients
        # A decryption passphrase can be added at any point as well, as long as cipher
        #  and sessionkey are also provided to enc_msg.encrypt
		# encryption is done using the public key from the public key file
        enc_pgp_msg = receiver_public_key.encrypt(pgp_msg, cipher=cipher, sessionkey=sessionkey)

        # do at least this as soon as possible after encrypting to the final recipient
        del sessionkey

        return str(enc_pgp_msg)
   

    def decrypt_file(self, encrypted_str_encoded_file):
        #print("encrypted_str_encoded_file")
        #print(encrypted_str_encoded_file)
        try:
            encrypted_pgp_message = pgpy.PGPMessage.from_file(encrypted_str_encoded_file)
            #print("encrypted_pgp_message")
            #print(encrypted_pgp_message)
            with receiver_private_key.unlock(receiver_private_key_pass_phrase):
                unenc_pgp_msg = receiver_private_key.decrypt(encrypted_pgp_message)
                #print("unenc_pgp_msg")
                #print(unenc_pgp_msg.message)
                return self.print_pgp_message_in_plain_text(unenc_pgp_msg)
        except ValueError:
            return "Not a valid PGP message. Likely Unencrypted password file"
            #return encrypted_str_encoded_file
            


#Static class that has static methods to create a unencrypted pwd entry object from a encrypted line, and
# and create a encrypted line with sourcename, username, password to be written to password file
class PWDLine():

    @staticmethod
    def makeADecryptedObjectFromLine(sourceLine):
        plainText = sourceLine
        if(len(plainText) > 0):
            #print(str(len(plainText)) + ' : ' + plainText)
            # now interpret fields by spitting the line to sourcename, username and password
            sublist = plainText.split(',')
            count = 1
            #print('field count on line:' + str(len(sublist)))
            for subc in sublist:
                #print(subc)
                #print(count)
                if(count == 1):
                    sourceName = subc
                    count = count + 1
                elif(count==2):
                    userName = subc
                    count = count + 1
                elif(count==3):
                    #print(count)
                    passwd = subc
                    count = count + 1
                else:
                    newPWDEntry = PWDEntry(sourceName,userName,passwd,subc)
                    count = count + 1

            #print('passwd:' + passwd + ' count: ' + str(count))
            #Fix for old entries with no "notes" field
            if(count == 4):
                newPWDEntry = PWDEntry(sourceName,userName,passwd,'')
        else:
            newPWDEntry = None
			
        return newPWDEntry

    @staticmethod
    def makeAEncryptedLine(currentPWDEntry):
        nextLine = currentPWDEntry.simpleSourceName() + ',' + currentPWDEntry.simpleUserName() + ',' + currentPWDEntry.simplePassword() + ',' + currentPWDEntry.simpleNotes()
        #print('Now encrypting line:' + nextLine)
        return nextLine

# class that will hold, pwd data
class PWDEntry():
    
    def __init__(self,sourceName,userName,password,notes):
        self.sourceName = sourceName
        self.userName = userName
        self.password = password
        self.notes = notes

    def simpleSourceName(self):
        return self.sourceName
    def simpleUserName(self):
        return self.userName
    def simplePassword(self):
        return self.password  
    def simpleNotes(self):
        return self.notes 
        
    def printinfo(self):
        print('Source Name is: ' + self.sourceName)
        print('User Name is: ' + self.userName)
        print('Password is: ' + self.password)
        if(len(self.notes) > 0):
            print('Notes is: ' + self.notes)

    def nextLine(self):
        nextLine = PWDLine.makeAEncryptedLine(self)
        return nextLine
    
    
class chosenPWDEntry():
    def __init__(self,chosenPWDEntry,chosenPWDEntryIndex):
        self.chosenPWDEntry = chosenPWDEntry
        self.chosenPWDEntryIndex = chosenPWDEntryIndex

def writeToFileOnly():
    newList = sorted(pwdList, key=lambda x: x.simpleSourceName(), reverse=False)
    with open(localPwdFile,'w') as file_object:
        for cc in newList:
            
            #print('base 64 encoded nextLine = ' + nextLine)
            # writing the encrypted pwd line entry, which is in bytes as string to be able to split them by line
            #To write something other than a string, it needs to be converted to a string first:
            nextLine = str(cc.nextLine())
            #nextLine = cc.nextLine()
            file_object.write(nextLine)
            file_object.write('\n')
        file_object.close()

    # now encrypt that file
    pgp_handler = pgp_encrypt_decrypt()
    enc_text = pgp_handler.encrypt_file(localPwdFile)
    with open(localPwdFile,'w') as file_object:
        file_object.write(enc_text)
        file_object.close()
        

def writeToS3():
    writeToFileOnly()

    #now upload the file to s3, as private file
    with open(localPwdFile, 'rb') as f:
            #now upload to s3
            s3Client.put_object(ACL='private',
              Bucket=BUCKET,
              Key=localPwdFile,
              Body=f,
              ServerSideEncryption='AES256')
            f.close()
    print("Updated s3")

def writeToFileAndS3():
    writeToFileOnly()
            
    #now upload the file to s3, as private file
    with open(localPwdFile, 'rb') as f:
            #now upload to s3
            s3Client.put_object(ACL='private',
              Bucket=BUCKET,
              Key=localPwdFile,
              Body=f,
              ServerSideEncryption='AES256')
            f.close()

    os.remove(localPwdFile)
    print("Done")
    exit()

def getNewPwdEntry():
    try:
        print('Press Ctrl+{0} to exit to main menu'.format('C'))
        print('Enter source name:')
        sourceName = input()
        print('Enter user name:')
        userName = input()
        print('Enter password:')
        password = input()
        print('Enter notes:')
        notes = input()
        newPWDEntry = PWDEntry(sourceName,userName,password,notes)
        pwdList.append(newPWDEntry)
    except KeyboardInterrupt:
        return
    except Exception as ex:
        print('Something went wrong with entering a new entry')
        return
    
def findPwdEntryByUserName(userName):
    foundPwdList = []
    count = 0
    for cc in pwdList:
        #print('searching in ' + cc.eventName + ' for ' + eventTitle)
        m = re.search('.*' + userName + '.*',cc.simpleUserName(), flags=re.IGNORECASE)
        if(m != None):
            foundPwdList.append(chosenPWDEntry(cc,count))
        count = count + 1
    #print(foundPwdList)
    
    count = 0
    if(len(foundPwdList) > 1):
        print()
        print('Multiple password entry matches. Matches:')
        printWithIndexList(foundPwdList)
        print('Please chose one')
        chosenOne = input()
        theOne = foundPwdList[int(chosenOne)]
    elif(len(foundPwdList) == 1):
        theOne = foundPwdList[0]
    else:
        print('No password entry found')
        return None
    return theOne

def findPwdEntryBySourceName(sourceName):
    foundPwdList = []
    count = 0
    for cc in pwdList:
        #print('searching in ' + cc.eventName + ' for ' + eventTitle)
        m = re.search('.*' + sourceName + '.*',cc.simpleSourceName(), flags=re.IGNORECASE)
        if(m != None):
            foundPwdList.append(chosenPWDEntry(cc,count))
        count = count + 1
    #print(foundPwdList)
    
    count = 0
    if(len(foundPwdList) > 1):
        print()
        print('Multiple password entry matches. Matches:')
        printWithIndexList(foundPwdList)
        print('Please chose one')
        chosenOne = input()
        theOne = foundPwdList[int(chosenOne)]
    elif(len(foundPwdList) == 1):
        theOne = foundPwdList[0]
    else:
        print('No password entry found')
        return None
    return theOne
	
def findPwdEntryByNotes(notes):
    foundPwdList = []
    count = 0
    for cc in pwdList:
        #print('searching in ' + cc.eventName + ' for ' + eventTitle)
        m = re.search('.*' + notes + '.*',cc.simpleNotes(), flags=re.IGNORECASE)
        if(m != None):
            foundPwdList.append(chosenPWDEntry(cc,count))
        count = count + 1
    #print(foundPwdList)
    
    count = 0
    if(len(foundPwdList) > 1):
        print()
        print('Multiple password entry matches. Matches:')
        printWithIndexList(foundPwdList)
        print('Please chose one')
        chosenOne = input()
        theOne = foundPwdList[int(chosenOne)]
    elif(len(foundPwdList) == 1):
        theOne = foundPwdList[0]
    else:
        print('No password entry found')
        return None
    return theOne

def printAllPwdEntries():
    #print('in printAllPwdEntries')
    count = 0
    print()
    for cc in pwdList:
        cc.printinfo()
        print()
        count = count + 1
    print()

def printWithIndexList(foundPwdList):
    #print('in printWithIndexList')
    count = 0
    print()
    for cc in foundPwdList:
        print(str(count) + '.')
        cc.chosenPWDEntry.printinfo()
        print()
        count = count + 1
    print()

def pwdEntryOptions(pwdEntry,pwdEntryType):
    printFBHeader(localPwdFile,len(pwdList))
    if(pwdEntryType == 'userName'):
            foundPwdEntry = findPwdEntryByUserName(pwdEntry)
    elif(pwdEntryType == 'sourceName'):
            foundPwdEntry = findPwdEntryBySourceName(pwdEntry)
    elif(pwdEntryType == 'notes'):
            foundPwdEntry = findPwdEntryByNotes(pwdEntry)
    if(foundPwdEntry != None):
            foundPwdEntry.chosenPWDEntry.printinfo()
    #copy password to clipboard
    try:
            pyperclip.copy(foundPwdEntry.chosenPWDEntry.simplePassword())
            print()
            print('Password copied to clipboard')
    except Exception:
            print()
            print('Password could not be copied to clipboard')

    selectedOption = 0
    print()
    print('Chose one of the password entry options')
    print('1.Exit to main menu')
    if(foundPwdEntry != None):
        print('2.Delete the password Entry')
        print('3.Copy Password to clipboard again')
        print('4.Update Source Name')
        print('5.Update User Name')
        print('6.Update Password')
        print('7.Update Notes')
        print('a.Save')
        print('q.Quit Without Save')
    
    while selectedOption != 8:
            selectedOption = input();
            if(str(selectedOption) == 'q'):
                    if(localPwdFile != None):
                            os.remove(localPwdFile)
                    exit()
            elif(str(selectedOption) == 'a'):
                    writeToS3() 
                    print('File Saved to S3')
            elif(int(selectedOption) == 1):
                    clearScreen()
                    return
            elif(int(selectedOption) == 2):
                    deletePWDEntry(foundPwdEntry)
                    return
            elif(int(selectedOption) == 3):
                    pyperclip.copy(foundPwdEntry.chosenPWDEntry.simplePassword())
                    print('Password copied to clipboard again')
            elif(int(selectedOption) == 6):
                    #update password
                    sourceName = foundPwdEntry.chosenPWDEntry.simpleSourceName()
                    userName = foundPwdEntry.chosenPWDEntry.simpleUserName()
                    notes = foundPwdEntry.chosenPWDEntry.simpleNotes()
                    print('Enter new password:')
                    password = input()
                    newPWDEntry = PWDEntry(sourceName,userName,password,notes)
                    pyperclip.copy(newPWDEntry.simplePassword())
                    deletePWDEntry(foundPwdEntry)
                    pwdList.append(newPWDEntry)
                    print('Password updated and copied to clipboard again')
            elif(int(selectedOption) == 4):
                    #update source name
                    notes = foundPwdEntry.chosenPWDEntry.simpleNotes()
                    userName = foundPwdEntry.chosenPWDEntry.simpleUserName()
                    passwd = foundPwdEntry.chosenPWDEntry.simplePassword()
                    print('Enter new source name:')
                    sourceName = input()
                    newPWDEntry = PWDEntry(sourceName,userName,passwd,notes)
                    pyperclip.copy(newPWDEntry.simplePassword())
                    deletePWDEntry(foundPwdEntry)
                    pwdList.append(newPWDEntry)
                    print('Source Name updated. Password copied to clipboard again')
            elif(int(selectedOption) == 5):
                    #update User Name
                    sourceName = foundPwdEntry.chosenPWDEntry.simpleSourceName()
                    notes = foundPwdEntry.chosenPWDEntry.simpleNotes()
                    passwd = foundPwdEntry.chosenPWDEntry.simplePassword()
                    print('Enter new User Name:')
                    userName = input()
                    newPWDEntry = PWDEntry(sourceName,userName,passwd,notes)
                    pyperclip.copy(newPWDEntry.simplePassword())
                    deletePWDEntry(foundPwdEntry)
                    pwdList.append(newPWDEntry)
                    print('User Name updated. Password copied to clipboard again')
            elif(int(selectedOption) == 7):
                    #update notes
                    sourceName = foundPwdEntry.chosenPWDEntry.simpleSourceName()
                    passwd = foundPwdEntry.chosenPWDEntry.simplePassword()
                    userName = foundPwdEntry.chosenPWDEntry.simpleUserName()
                    print('Enter new notes:')
                    notes = input()
                    newPWDEntry = PWDEntry(sourceName,userName,passwd, notes)
                    pyperclip.copy(newPWDEntry.simplePassword())
                    deletePWDEntry(foundPwdEntry)
                    pwdList.append(newPWDEntry)
                    print('Notes updated. Password copied to clipboard again')
           
    
def deletePWDEntry(entryToBeDeleted):
    del pwdList[entryToBeDeleted.chosenPWDEntryIndex]
    return


def isLinuxOS():
    if platform == "linux" or platform == "linux2":
        return 'yes'
    else:
        return 'no'
    
def isWindowsOS():
    if platform == "win32":
        return 'yes'
    else:
        return 'no'

def clearScreen():
    if(isLinuxOS() == 'yes'):
        os.system('clear')
    elif(isWindowsOS() == 'yes'):
        os.system('cls')

# not used as of 2018-02-19
def decryptAWSSecretKey(aws_secret_key,aws_pwd):
	#create PGP message from the encrypted AWS secret access key (encrypted using the AWS Password)
    pgp_msg = pgpy.PGPMessage.from_blob(aws_secret_key)
	#decrypt the AWS secret access key (using the provided AWS Password)
    plainText = pgp_msg.decrypt(aws_pwd)
    print(plainText.message)
    pyperclip.copy(plainText.message)
    return plainText.message

def printFBHeader(processing_file, pwdListLen):
    print(' ************ PROCESSING PASSWORDS FILE - PGP for ' + processing_file + ' (' + str(pwdListLen) + ') ************ ')
    print(' ************ use strong passwords from passwordgenerator.net or password store app  ************ ')
    print(' ************ use secret_answer_right_shifter.py for secret question answers and note shift in notes  ************ ')



# Creat a AWS client connection to S3 using AWS access key & (decrypted) AWS secret access key
s3Client = boto3.client(
's3',
aws_access_key_id=aws_access_key,
aws_secret_access_key=aws_secret_key
)

print('Specify the Pass Phrase for Private Key (same for all files)')
try:
	# This is the passphrase that is used to decrypt the PGP private key, which is needed to decrypt the password file
    receiver_private_key_pass_phrase = getpass.getpass(prompt='Pass Phrase:')
except Exception:
    #print('Password maybe displayed back')
    receiver_private_key_pass_phrase = input()


localPwdFile = None
s3PwdFile = None
# for test set s3PwdFile = 't2'

if(s3PwdFile == None):
    print('Specify the password file to load')
    s3PwdFile = input()
    
if(s3PwdFile != None and len(s3PwdFile) != 0):
    try:
        s3Client.download_file(BUCKET,s3PwdFile,s3PwdFile)
        localPwdFile = s3PwdFile
        # now encrypt that file
        pgp_handler = pgp_encrypt_decrypt()
        dec_text = pgp_handler.decrypt_file(localPwdFile)
##      print("dec_text")
##      print(dec_text)
        if(dec_text == "Not a valid PGP message. Likely Unencrypted password file"):
            # likely the file is plain old text file. let us try to split lines from it, the old way
            with open(localPwdFile ) as infile_object :
             lines = infile_object.read().splitlines() # strips the newline at end of line
             infile_object.close()
        else:
            lines = dec_text.split('\n') # strips the newline at end of line
    except Exception:
        #continue if file not found
        localPwdFile = s3PwdFile
        print('File not found. Creating new password file ' + localPwdFile)
        infile_object = open(localPwdFile,'w')
        lines = []
        infile_object.close()


# declare a list to hold events
pwdList = []

# load events from data file into the list
for line in lines:
    newPWDEntry = PWDLine.makeADecryptedObjectFromLine(line)
    if(newPWDEntry != None):
        pwdList.append(newPWDEntry)
    
#pwdList = sorted(pwdList, key=lambda x: x.sourceName, reverse=False)

clearScreen()
# main driver
selectedOption = 0
while selectedOption != 9 and str(selectedOption) != 'q':
    printFBHeader(localPwdFile,len(pwdList))
    print('Chose one of the options')
    print('1.Add a password entry')
    print('2.Locate a password entry by source name')
    print('3.Locate a password entry by user name')
    print('4.Locate a password entry by notes')
    print('5.List all password entries')
    print('a.Save to S3')
    print('b.Save to Local only')
    print('9.Quit With Save')
    print('q.Quit Without Save')
    selectedOption = input();
    if(str(selectedOption) == 'q'):
        if(localPwdFile != None):
            os.remove(localPwdFile)
        exit()
    elif(str(selectedOption) == 'a'):
        writeToS3()
        clearScreen()
    elif(str(selectedOption) == 'b'):
        writeToFileOnly()
        clearScreen()
    elif(int(selectedOption) == 9):
      writeToFileAndS3()
    elif(int(selectedOption) == 1):
        clearScreen()
        getNewPwdEntry()
        clearScreen()
    elif(int(selectedOption) == 2):
       print('Enter source name of password entry (to search)')
       pwdEntry = input()
       clearScreen()
       pwdEntryOptions(pwdEntry,'sourceName')
       clearScreen()
    elif(int(selectedOption) == 3):
       print('Enter user name of password entry (to search)')
       pwdEntry = input()
       clearScreen()
       pwdEntryOptions(pwdEntry,'userName')
       clearScreen()
    elif(int(selectedOption) == 4):       
       print('Enter notes of password entry (to search)')
       pwdEntry = input()
       clearScreen()
       pwdEntryOptions(pwdEntry,'notes')
       clearScreen()
    elif(int(selectedOption) == 5):
       clearScreen()
       printFBHeader(localPwdFile,len(pwdList))
       print('Listing all password entries')
       printAllPwdEntries()
