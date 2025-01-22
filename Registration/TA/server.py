import socket
import hashlib
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1, NIST256p
import redis
import mysql.connector
import struct

HOST = '127.0.0.1'
PORT = 12346

def publish_apkey(c1, c2):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c2_x = c2.x().to_bytes(32, byteorder = 'big')
    c2_y = c2.y().to_bytes(32, byteorder = 'big')

    c1_c2 = c1_x + c1_y + c2_x + c2_y

    hash_result = hashlib.sha256(c1_c2).digest()
    print("hash: "+hash_result.hex())

    redis_client = redis.StrictRedis(host='localhost', port = 6379, db = 0)
    redis_client.set(hash_result, c1_c2)
    return hash_result
    


def private_store(c1,c3, cid):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c3_x = c3.x().to_bytes(32, byteorder = 'big')
    c3_y = c3.y().to_bytes(32, byteorder = 'big')
    
    cnx = mysql.connector.connect(user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID')
    cursor = cnx.cursor()

    insert_query = ("INSERT INTO cid_store" 
                    "(cid, c1_x, c1_y, c3_x, c3_y, current_i)"
                    "VALUES (%(cid)s, %(c1_x)s, %(c1_y)s, %(c3_x)s, %(c3_y)s, %(current_i)s)")
    
    data_cid = {
        'cid': cid,
        'c1_x': c1_x,
        'c1_y': c1_y,
        'c3_x': c3_x,
        'c3_y': c3_y,
        'current_i': 1
    }
    cursor.execute(insert_query, data_cid)
    cnx.commit()
    cursor.close()

    cnx.close()




def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"Server listening on {HOST}:{PORT}")
    msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)

    try:
        while True:
            client_socket, client_adddress = server_socket.accept()
            print(f"Connection established with {client_adddress}")
            data = client_socket.recv(64)
            if len(data) != 64:
                print(f"Invalid data length: {len(data)} bytes received")
                client_socket.close()
                continue
            x_bytes = data[:32]
            y_bytes = data[32:]
            x = int.from_bytes(x_bytes, byteorder='big')
            y = int.from_bytes(y_bytes, byteorder='big')

            curve = NIST256p.curve
            pk = Point(curve, x, y)
            mpk = msk * NIST256p.generator
            print(f"Public key recieved \npk_x:{hex(pk.x())}\npk_y:{hex(pk.y())}")
            
            u = int("5e5205324863018f4f9454c699eb160688355046e66418647c51b302a90ffd72", 16)
            
            pk_bytes = x_bytes + y_bytes
            byte_representation = struct.pack('I', 1)
            pk_bytes += byte_representation
            hash_result = hashlib.sha256(pk_bytes).hexdigest()
            u = int(hash_result, 16)


            
            c1 = u * NIST256p.generator
            c2 = (u + 1) * pk
            c3 = u * mpk + pk
            print(f"\nc1_x:{hex(c1.x())}\nc1_y:{hex(c1.y())}")
            print(f"\nc2_x:{hex(c2.x())}\nc2_y:{hex(c2.y())}")
            print(f"\nc3_x:{hex(c3.x())}\nc3_y:{hex(c3.y())}\n\n")
            
            cid = publish_apkey(c1, c2)
            private_store(c1, c3, cid)
            client_socket.sendall(cid)
            


    except KeyboardInterrupt:
        print("server shutting down")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
