from ecdsa import SigningKey, NIST256p, VerifyingKey
import ecdsa.util
import hashlib
import codecs
from datetime import date
import re
from binascii import hexlify, unhexlify, b2a_base64
from OpenSSL import crypto
from OpenSSL.crypto import FILETYPE_PEM, FILETYPE_ASN1, FILETYPE_TEXT
import asn1
import binascii
import base64
import os.path

d=date.today()
date=str(d)

def gen_cert():
    #### Set CA Private key ####
    ca_sk=SigningKey.from_pem(open("ca-key.pem").read())
    ca_vk=VerifyingKey.from_pem(open("ca-pubkey.pem").read())

 
    #serial number
    sn_n=input("Serial Number (21characters)  ")
    while len(sn_n) != 21:
        print ('Wrong Length')
        sn_n=input("Serial Number (21characters)  ")
    try:
        os.mkdir(sn_n)
    except:
        print ("Already Existing")
        restart()        
    sn=sn_n.encode('utf-8')
    sn_as=hexlify(sn)



    #reseller id
    re_id=input("Reseller ID (8characters)  ")
    while len(re_id) != 8:
        print("Wrong Length")
        re_id=input("Reseller ID (8characters)  ")

    re_id=re_id.encode('utf-8')
    re_id=hexlify(re_id)

    
    #time    
    today=re.findall('[0-9]',date)
    timstamp=''
    for i in today:
        timstamp=timstamp+i
    timstamp=timstamp.encode('utf-8')
    timstamp_as=hexlify(timstamp)
    
    #version
    version=input("Version  ")
    version=int(version)
    v='0x%0*X' %(4,version)
    v=v[2:]
    


    #Satoshi Value
    sato_val=input("Satoshi Value (Satoshi Value should be a non-zero positive integer)  ")
    sato_val=int(sato_val)
    s='0x%0*X' %(8,sato_val)
    s=s[2:]
    

    #Raw Certificate (without public key)
    basic_info=sn_as+re_id+timstamp_as
    bin_data=v+s
    bin_data=bin_data.encode('utf-8')
    raw_cert=basic_info+bin_data


    #Generate money key pair
    m_sk=SigningKey.generate(curve=NIST256p)
    m_vk=m_sk.get_verifying_key()
    

    #Export money key pair
    m_vk_pem=m_vk.to_pem()
    m_sk_pem=m_sk.to_pem()
    with open(os.path.join(sn_n,sn_n+"_key.pem"),"wb") as file1:    
        file1.write(m_vk_pem)
        file1.write(b'\r\n')
        file1.write(m_sk_pem)

    #Set public key bianry
    m_vk_st=m_vk.to_string()
    m_publickey=binascii.hexlify(bytearray(m_vk_st))

    #Set unsigned certificate
    unsigned_cert=raw_cert+m_publickey
       
    unsigned_cert=binascii.unhexlify(bytearray(unsigned_cert))
    

    #Sign the unsigned certificate with CA public key
    signature=ca_sk.sign(unsigned_cert,hashfunc=hashlib.sha256)
    signature_hash=hashlib.sha256(unsigned_cert).hexdigest()    
    assert ca_vk.verify(signature,unsigned_cert,hashfunc=hashlib.sha256)  

    signature_re=binascii.hexlify(bytearray(signature))   

    unsigned_cert=binascii.hexlify(bytearray(unsigned_cert))
    cert=unsigned_cert+signature_re    

    #Encode using base64
    cert_=binascii.unhexlify(cert)
    result=binascii.b2a_base64(cert_)
    

    with open(os.path.join(sn_n,sn_n+"_cert.pem"),"wb") as file3:
        file3.write(result)
    

def ver_cert():

    #select file and restore its binary value
    sn_n=input("Serial Number (21characters)  ")
    while len(sn_n) != 21:
        print ('Wrong Length')
        sn_n=input("Serial Number (21characters)  ")
    try:
        with open(os.path.join(sn_n,sn_n+"_cert.pem"),"rb") as file5:
            r_cert=file5.read()
    except:
        print ("Not Existing")
        restart()

    
    b_cert=base64.b64decode(r_cert)       
    
    #define binary values
    serial_number=b_cert[:21]
    reseller_id=b_cert[21:29]
    issue_date=b_cert[29:37]
    #print (serial_number,reseller_id,issue_date) #check
    
    b_data=binascii.hexlify(b_cert)
    b_data_c=binascii.hexlify(b_cert[37:])
    #print (b_data,'\n',b_data_c) #check
    
    version=b_data_c[:4]
    version=int(version,16)
    satoshi_value=b_data_c[4:12]
    satoshi_value=int(satoshi_value,16)
    #print (version,satoshi_value)  #check
        

    #verify certification
    ca_vk=VerifyingKey.from_pem(open("ca-pubkey.pem").read())
    signature=b_data[214:]
    signature=binascii.unhexlify(bytearray(signature))
    
    unsigned_data=b_data[:214]
    unsigned_data=binascii.unhexlify(bytearray(unsigned_data))
    
    
    assert ca_vk.verify(signature,unsigned_data,hashfunc=hashlib.sha256)
    print (sn_n,"  Verification Succeeded")
    print ("Reseller ID: ",reseller_id.decode('utf-8'))
    print ('Issue Date: ',issue_date.decode('utf-8'))
    print ('Version: ',version)
    print ('Satoshi Value: ',satoshi_value)

def restart():
    while True:
        print ("Press 1 if you want to generate a certificate. \nPress 2 if you want to verify a certificate.")
        command=input("1 or 2  ")
        if command=="1":
            gen_cert()
        if command=="2":
            ver_cert()
            
while True:
    print ("Press 1 if you want to generate a certificate. \nPress 2 if you want to verify a certificate.")
    command=input("1 or 2  ")
    if command=="1":
        gen_cert()
    if command=="2":
        ver_cert()
