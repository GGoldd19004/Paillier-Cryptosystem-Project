import socket
import json
from phe import paillier

public_key, private_key = paillier.generate_paillier_keypair()

secret_number_list = []

def client_program():
    host = socket.gethostname()  
    port = 5000  

    client_socket = socket.socket()  
    client_socket.connect((host, port))  
    
    i = 0
    while i<3:
    	message = input(" -> ")
    	secret_number_list.append(int(message))
    	i+=1
    	
    encrypted_number_list = [public_key.encrypt(x) for x in secret_number_list]
    enc_with_one_pub_key = {}
    enc_with_one_pub_key['public_key'] = {'g': public_key.g,
    					  'n': public_key.n}
    enc_with_one_pub_key['values'] = [
    	(str(x.ciphertext()), x.exponent) for x in encrypted_number_list
    ]
    serialized = json.dumps(enc_with_one_pub_key)
    client_socket.send(serialized.encode())  
    
    data = client_socket.recv(1073741824).decode() 
    
    received_dict = json.loads(data)
    enc_nums_rec = [
	    paillier.EncryptedNumber(public_key, int(x[0]), int(x[1]))
	    for x in received_dict['values']
    ]
    f = [private_key.decrypt(x) for x in enc_nums_rec]
    print(f)

    client_socket.close()
    
if __name__ == '__main__':
    client_program()
