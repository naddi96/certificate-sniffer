import sqlite3
from datetime import datetime
from sqlite3 import Error
import json

database="./db/sqlite.db"

def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)




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



def create_db():
    sql_create_projects_table = """ CREATE TABLE IF NOT EXISTS certificati (
                                        id integer PRIMARY KEY,
                                        hash text UNIQUE NOT NULL,
                                        certificato BLOB NOT NULL,
                                        frequenza INTEGER NOT NULL,
                                        CA text NOT NULL,
                                        data_visione integer  NOT NULL,
                                        data_scadenza integer NOT NULL,
                                        data_emissione integer NOT NULL
                                    ); """

    sql_create_tasks_table = """CREATE TABLE IF NOT EXISTS nomi_domino (
                                    id integer PRIMARY KEY,
                                    nome text UNIQUE NOT NULL,
                                    certificato integer NOT NULL,
                                    FOREIGN KEY (certificato) REFERENCES certificati (id)
                                );"""

    # create a database connection
    conn = create_connection()
    print(conn)
    # create tables
    if conn is not None:
        # create projects table
        create_table(conn, sql_create_projects_table)

        # create tasks table
        create_table(conn, sql_create_tasks_table)
    else:
        print("Error! cannot create the database connection.")





if __name__ == '__main__':
    conn = create_connection()
    with conn:
        rows=get_certificate("%.vortex.data.microsoft.com",conn)  
        x=json.loads(rows[0][5])
        print(len(x))