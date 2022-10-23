# Bitcoin-ECC-Signature

The codes generate key pairs and sign transcations with the private key.
The data formats are as follows:

Hex format of a Certificate  
413030303030303030303030303030303030303031  
3030303030303031  
3230313830363031  
0001  
000F4240  
BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC31667CB477A1A8EC338F94741669C976316DA6321  
340E7BE2A280EB74E2BE61BADA745D97E8F7C3001E589A8595423412134FAA2DBDEC95C8D8675E58

Where each line means:
SN  
Reseller ID  
Issue Date  
Version  
Satoshi Value  
Money Public Key  
Signature  

Certificate Base-64 Version
QTAwMDAwMDAwMDAwMDAwMDAwMDAxMDAwMDAwMDEyMDE4MDYwMQABAA9CQL7VrxbqP2pPYpOMRjHrWve9vNvDFmfLR3oajsM4+UdBZpyXYxbaYyE0DnviooDrdOK+YbradF2X6PfDAB5YmoWVQjQSE0+qLb3slcjYZ15Y

## Prepare CA ECC keypair
$ openssl ecparam -name prime256v1 -genkey -noout -out ca-key.pem  
$ openssl ec -in ca-key.pem -text -noout  
read EC key  
Private-Key: (256 bit)  
priv:  
    78:f0:ce:34:b6:25:1a:a8:ec:d3:1e:47:dd:ec:2b:  
    44:e0:e6:94:03:a1:01:f3:48:a1:3e:c3:c0:41:cc:  
    97:61  
pub:  
    04:c0:49:a8:c8:fb:f1:3f:1c:95:27:a0:08:ea:10:  
    9f:61:ff:8e:f7:78:41:92:f0:3c:5d:98:07:c5:e0:  
    b1:f6:aa:47:1c:34:ea:b3:dc:4d:39:e7:bb:0f:e7:  
    dd:8c:12:1c:ec:e6:f4:54:24:01:8f:d9:fd:ff:a9:  
    4c:28:4b:e1:b3  
ASN1 OID: prime256v1  
NIST CURVE: P-256  



Detailed spec: https://docs.google.com/document/d/1QEvaFAu5Q7r29d5PFH_RvzR_xMwxVxoF/edit?usp=sharing&ouid=113374654964338736968&rtpof=true&sd=true



