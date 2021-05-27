import sqlite3
from datetime import datetime
from sqlite3 import Error
import json

database="./db/sqlite.db"

def create_connection():
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(database)
        return conn
    except Error as e:
        print(e)

    return conn


def get_certificate(name,conn):
    cur = conn.cursor()
    cur.execute("""select 
    certificati.hash , certificati.frequenza,certificati.id, certificati.data_scadenza, certificati.CA, certificati.certificato
            from nomi_domino join certificati 
            where ? = nomi_domino.nome 
            and nomi_domino.certificato= certificati.id""", (name,))
    rows = cur.fetchall()
    return rows





def insert_certificate(cert_data,conn):
    now = datetime.now()
    timestamp = datetime.timestamp(now)
    ce = (cert_data['sha256'],cert_data['certificate'], 1, cert_data['CA'],timestamp, cert_data['valid_to'],cert_data['valid_from'])
    sql = ''' INSERT INTO certificati(hash,certificato,frequenza,CA,data_visione,data_scadenza,data_emissione)
    VALUES(?,?,?,?,?,?,?)'''
    cur = conn.cursor()
    cur.execute(sql, ce)
    cert_row_id=cur.lastrowid
    conn.commit()

    for dns in cert_data['dns']:
        ce = (dns,cert_row_id)
        sql = ''' INSERT INTO nomi_domino(nome,certificato)
        VALUES(?,?) '''
        cur = conn.cursor()
        cur.execute(sql, ce)
    conn.commit()


def update_All_certificate(id,freq,hash,cert,conn):
    sql = ''' update certificati set frequenza=? , hash=? , certificato=? , data_visione=? where certificati.id=? '''
    now = datetime.now()
    timestamp = datetime.timestamp(now)
    cur = conn.cursor()
    cur.execute(sql, (freq,hash,cert,timestamp,id))
    conn.commit()


def update_Freq_certificate(id,freq,conn):
    sql = ''' update certificati set frequenza=? , data_visione=? where certificati.id=? '''
    now = datetime.now()
    timestamp = datetime.timestamp(now)
    cur = conn.cursor()
    cur.execute(sql, (freq,timestamp,id))
    conn.commit()


if __name__ == '__main__':
    conn = create_connection()
    with conn:
        rows=get_certificate("%.vortex.data.microsoft.com",conn)  
        x=json.loads(rows[0][5])
        print(len(x))