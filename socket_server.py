import socket
import json
from phe import paillier

def server_program():
    host = socket.gethostname()
    port = 5000  

    server_socket = socket.socket()  
    server_socket.bind((host, port))  

    server_socket.listen(1)
    conn, address = server_socket.accept() 
    print("Connection from: " + str(address))
    
    
    g = 0
    n = 0
    data = conn.recv(1073741824).decode()
    received_dict = json.loads(data)
    pk = received_dict['public_key']
    public_key_rec = paillier.PaillierPublicKey(int(pk['n']))

    enc_nums_rec = [
	    paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1]))
	    for x in received_dict['values']
    ]
    x1, x2, x3 = enc_nums_rec
    
    a1 = 5
    a2 = 6
    a3 = 7
    b = 8  
    
    encrypted_y1 = a1 * x1 
    encrypted_y2 = a2 * x2
    encrypted_y3 = a3 * x3
    encrypted_y4 = encrypted_y1+encrypted_y2+encrypted_y3
    encrypted_y = encrypted_y4+b
    
    encrypted_number_list = [encrypted_y]
    enc_with_one_pub_key = {}
    enc_with_one_pub_key['public_key'] = {'g': public_key_rec.g, 'n': public_key_rec.n}
    enc_with_one_pub_key['values'] = [
    	(str(x.ciphertext()), x.exponent) for x in encrypted_number_list
    ]
    serialized = json.dumps(enc_with_one_pub_key)
    conn.send(serialized.encode())
            
    conn.close() 


if __name__ == '__main__':
    server_program()
