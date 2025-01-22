import socket
import hashlib
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1, NIST256p
import redis
import mysql.connector



msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)


def trace_id(cid):
    cnx = mysql.connector.connect(user = 'TAServer',
                                  password = '123456',
                                  host = '127.0.0.1',
                                  database = 'PRIVATE_ID')
    
    cursor = cnx.cursor()

    find_id_query = ("SELECT c1_x, c1_y, c3_x, c3_y, current_i FROM cid_store WHERE cid = %(cid)s")
    cursor.execute(find_id_query, {'cid':cid})

    result = cursor.fetchone()
    
    c1_x, c1_y , c3_x, c3_y, current_i = result
    
    cursor.close()
    cnx.close()

    curve = NIST256p.curve
    
    c1_x = int.from_bytes(c1_x, byteorder = 'big')
    c1_y = int.from_bytes(c1_y, byteorder = 'big')
    c3_x = int.from_bytes(c3_x, byteorder = 'big')
    c3_y = int.from_bytes(c3_y, byteorder = 'big')
    c1_y = -c1_y
   
    c1 = Point(curve, c1_x, c1_y)
    c3 = Point(curve, c3_x, c3_y)
    pk = c3 + (msk * c1)

    
    pk_x = pk.x()
    print(hex(pk_x))
    pk_y = pk.y()
    print(hex(pk_y))


cid = int(input(),16).to_bytes(32, byteorder='big')
trace_id(cid)
