#!/usr/bin/python
# -*- coding: utf-8 -*-
import hashlib
import crypt
import sys
banner = '''
*********************************************************
*     \                                           |     *
*    _ \      __|    __|    _ \   __ \     _` |   |     *
*   ___ \    |     \__ \    __/   |   |   (   |   |     *
* _/    _\  _|     ____/  \___|  _|  _|  \__,_|  _|     *
*                                                  v1.0 *
******************************************By-Sumit Ojha *
*******************************************ICS-CloudSec *                                                   
'''
def decrypter(cryptpass, salt):
    dict_file = open('dictionary.txt', 'r')
    for word in dict_file.readlines():
        word = word.strip('\n')
        cryptword = crypt.crypt(word, salt)
        if cryptpass == cryptword:
            print 'password found:>>> ' + word +'\n'
            return
    dict_file.close()
#     print "CAnt found the password for ", user   
    return

def hash_lib(cryptpass, usr_input):
    dict_file = open('dictionary.txt', 'r')
    for word in dict_file.readlines():
        word = word.strip('\n')
        if usr_input == '3':   cryptword = hashlib.md5(word).hexdigest()
        elif usr_input == '4': cryptword = hashlib.sha1(word).hexdigest()
        elif usr_input == '5': cryptword = hashlib.sha224(word).hexdigest()
        elif usr_input == '6': cryptword = hashlib.sha256(word).hexdigest()
        elif usr_input == '7': cryptword = hashlib.sha384(word).hexdigest()
        elif usr_input == '8': cryptword = hashlib.sha512(word).hexdigest()

        if cryptword == cryptpass:
            print 'password found:>>> ' + word + '\n'
            return
    return
def passopen(usr_input):

    pass_file = open('passwords.txt', 'r')
    for line in pass_file.readlines():
        if ':' in line:
            user = line.split(':')[0]
            cryptpass = line.split(":")[1].strip(' ')
            cryptpass = cryptpass.strip()
            print '[*] Cracking Password For: ' + user
            hash_lib(cryptpass, usr_input)


def sanitize_input(usr_input, i_min, i_max):
    try:
        inp = int(usr_input)
        choice(usr_input)
    except ValueError:
        print 'Input must be an integer'
        return None
    if not i_min <= inp <= i_max:    #if not 1 <= 5 <= 2
        print 'Input must be between {} and {}'.format(i_min, i_max)
        return None
    else:
        inp

def choice(usr_input):
    global user
    if usr_input == '1' :
        pass_file = open('passwords.txt', 'r')
        for line in pass_file.readlines():
            if ':' in line:
                user = line.split(':')[0]
                cryptpass = line.split(':')[1].strip(' ')
                salt = cryptpass[0:2]
                print '[*] Cracking Password For: ' + user
                decrypter(cryptpass, salt)
 
    elif usr_input == '2':
        pass_file = open('passwords.txt', 'r')
        for line in pass_file.readlines():
            if '$' in line:
                user = line.split(':')[0]
                cryptpass = line.split(":")[1].strip(' ')
                salt = cryptpass.split('$')[2]
                if '$6$' in line:   salt = '$6$' + salt
                elif '$1$' in line: salt = '$1$' + salt
                elif '$2$' in line: salt = '$2$' + salt
                elif '$3$' in line: salt = '$3$' + salt
                elif '$4$' in line: salt = '$4$' + salt
                elif '$5$' in line: salt = '$5$' + salt
                
                print '[*] Cracking Password For: ' + user
                decrypter(cryptpass, salt)
                 
    elif usr_input == '3' or usr_input == '4' or usr_input == '5':
        passopen(usr_input)

    elif usr_input == '6' or usr_input == '7' or usr_input == '8':
        passopen(usr_input)
    elif usr_input == '9':
        sys.exit()
    
def main():
    print banner
    print "|Choose the hash, You want to decrypt"
    print "|1: Unix hash"
    print "|2: Shadow Cracker"
    print "|3: MD5"
    print "|4: SHA"
    print "|5: SHA224"
    print "|6: SHA256"
    print "|7: SHA384"
    print "|8: SHA512"
    print "|9: Quit"
    
    mode = None
    while not mode:
        mode = sanitize_input(raw_input("\nEnter: "), 1, 9)     
        
if __name__ == '__main__':
    main()
