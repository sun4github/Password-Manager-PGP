# Password-Manager-PGP
Password manager with PGP and S3 support

Goal:
To securely save passwords, in cloud and retrieve them in a secure fashion.

Brief Summary:
- Allows password entries will be saved in a password file
- each password entry incorporates following fields: source name, user name, password and notes 
- All fields in password entry are comma seperated
- All contents (lines of password entries) of the password file will be encrypted using PGP public key
- All contents (lines of password entries) of the password file will be decrypted using PGP private key
- Password file is stored in S3 bucket, as a AES-256 bit encrypted object

Dependencies:
- Python (3+)
- Internal Modules (from standard library): 
    datetime, re, os, match, getpass, sy, hashlib, warnings
- External Modules (need installation): 
    boto3 (for AWS SDK), 
    pgpy (Python port of PGP encryption), 
    pyperclip (for Clipboard functionality),
 - AWS Cloud Account 
 - AWS S3 Bucket
 - PGP Public & Private keys ( Can be generated using Gpg4win tools )
    
Details:
  Password manager addresses the issue of remembering, the ever-increasing number of passwords, that are a part
  and parcel of our modern digital life. As we sign-up and utilize more and more services and equipment, the need
  to secure them with hard to guess passwords, becomes ever-so important. However, as human-beings there is a limit
  on how many things one can remember in our already cramped cranium. 
  
  Password manager is a attempt, to make the job of remembering so many passwords easy by using a computer program and 
  the ominipresent cloud technologies, to remember those pesky passwords. 
  
  While, there are many excellent "password store" solutions out there, it has always been my personal concern not to 
  trust my passwords with external apps, and especially the closed-source ones. This password manager is a open-source
  solution to the password store.
  
  HOW TO GET STARTED ? (Coming up soon)
   - read INSTALLATION GUIDE
   - read SETUP GUIDE
   - read USER GUIDE
