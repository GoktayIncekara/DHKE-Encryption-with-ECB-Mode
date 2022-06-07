#260201037 - 250201012
#When compiling the code in the ubuntu terminal, python3 should be added in the beginning of each command
#For example: >>python3 bob.py dhke -b 3 -A 4 -p 23

from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import base64

import sys
from random import randint

BLOCK_SIZE = 32

#color codes for the extra part
START_GREEN = '\033[92m'
START_RED = '\033[93m'
START_CYAN = '\033[96m'
END_COLOR = '\033[0m'
BOLD = '\033[1m'


def checkPrime(num):
    if(num==0 or num==1):
        return False
    for i in range(2, num):
        if (num%i == 0):
            return False
    return True  

def primitiveRoot(num,prime):
    control = set()
    for i in range(1,prime):
        number = (num**i) % prime
        control.add(number)
    if (len(control)==(prime-1)):
        return True
    else:
        return False
    
def randomNumber():
    return randint(1,10)

def trailingSpaces(plainText):
    trailingSpaces = len(plainText) % 8 #takes the remainder of the division of the plain text's length with 8
    trailingSpaces= 8- int(trailingSpaces) #and finds the needed number to complete the length to a multiply of 8 
    return plainText + (b' ' * trailingSpaces)

def main():
    p=0
    g=0
    a=0
    B=0
    A=0
    s=0
    k=0
    
    if (sys.argv[1]=="dhke"):
        if(len(sys.argv)==6):
            if(sys.argv[2] == "-g" and sys.argv[4]=="-p"):
                g = sys.argv[3]
                p = sys.argv[5]
            elif (sys.argv[2] == "-p" and sys.argv[4]=="-g"):
                p = sys.argv[3]
                g = sys.argv[5]
            else:
                raise Exception("Please provide p and g to initialize the key.")    
                
            p= int(p)
            g= int(g)
            

            if (checkPrime(p)== False):
                print("This is not a prime number. Exiting the system!")
                sys.exit()
            else:
                print("p = ", p , START_GREEN + 'OK' + END_COLOR, START_RED +"(This is a prime number.)"+END_COLOR)
                
            if (primitiveRoot(g,p)==False):
                print("This is not a primitive root. Exiting the system!")
                sys.exit()
            else:
                print("g = ", g  ,START_GREEN + 'OK' + END_COLOR, START_RED + "(This is a primitive root modulo ", p,".)" + END_COLOR)
            print("Alice and Bob publicly agree on the values of p and g.")
            print("However, it is advised to use any pair of p and g only once.")
                
            b = randomNumber()    #generates private key of Bob as a random number 
            B = (g**a)%p   #computes the public key of Bob
            print("b = ", b,  BOLD +" (This must be kept secret.)"+ END_COLOR)
            print("B = ", B, BOLD + " (This can be sent to Alice.)" + END_COLOR)

        elif (len(sys.argv)==8):
            if(sys.argv[2] == "-b" and sys.argv[4]=="-A" and sys.argv[6]=="-p"):
                b = sys.argv[3]
                A = sys.argv[5]
                p = sys.argv[7]
            elif(sys.argv[2] == "-b" and sys.argv[4]=="-p" and sys.argv[6]=="-A"):
                b = sys.argv[3]
                p = sys.argv[5]
                A = sys.argv[7]
            elif(sys.argv[2] == "-p" and sys.argv[4]=="-b" and sys.argv[6]=="-A"):
                p = sys.argv[3]
                b = sys.argv[5]
                A = sys.argv[7]
            elif(sys.argv[2] == "-p" and sys.argv[4]=="-A" and sys.argv[6]=="-b"):
                p = sys.argv[3]
                A = sys.argv[5]
                b = sys.argv[7]
            elif(sys.argv[2] == "-A" and sys.argv[4]=="-p" and sys.argv[6]=="-b"):
                A = sys.argv[3]
                p = sys.argv[5]
                b = sys.argv[7]
            elif(sys.argv[2] == "-A" and sys.argv[4]=="-b" and sys.argv[6]=="-p"):
                A = sys.argv[3]
                b = sys.argv[5]
                p = sys.argv[7]
            else:
                raise Exception("Please provide b, p and A to calculate the key.")
                
            A = int(A) 
            b = int(b)
            p = int(p)    
            
            s = (B**a)%p   #generates the secret number between Bob and Alice
            print(START_RED +"s = "+ END_COLOR, s )
            print("This must be kept secret. However, Alice should be able to calculate this as well.")
        else:
            raise Exception("Please provide p and g to initialize the key exchange or provide a,p and B to calculate the key.")
    
    elif (sys.argv[1]=="des"):

        if(sys.argv[2] == "-c" and sys.argv[4]=="-k"):
            c = sys.argv[3]
            k = sys.argv[5]
        elif (sys.argv[2] == "-k" and sys.argv[4]=="-c"):
            k = sys.argv[3]
            c = sys.argv[5]
        else:
            raise Exception("Please provide the ciphertext and a key.")    
            
        zero_amount= 8-len(k) #the zero amount which will be needed to complete the key's length to 8
        byte_key=k
        
        for i in range(0,zero_amount):  #puts the zeros to the beginning of the key
            byte_key= '0'+byte_key 
            
        key=bytes(byte_key, 'ascii')   #converts string to byte
         
        decipher = DES.new(key, DES.MODE_ECB)
        byte_decipher = c.encode()  #converts ciphertext to byte
        raw_ciphertext= base64.b64decode(byte_decipher) #converts readable ciphertext to raw ciphertext
        msg_dec = decipher.decrypt(raw_ciphertext) #decrypts ciphertext with using DES and ECB 
        unpad_mes=unpad(msg_dec, BLOCK_SIZE) #unpads decrypted plaintext
        print(START_CYAN+'Decrypted plaintext:\n'+END_COLOR,unpad_mes.decode())

main()        