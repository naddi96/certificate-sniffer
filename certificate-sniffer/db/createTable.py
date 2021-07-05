import sqlite3
from sqlite3 import Error


def create_table(conn, create_table_sql):
    try:
        c = conn.cursor()
        c.execute(create_table_sql)
    except Error as e:
        print(e)


def create_connection(db_file):
    """ create a database connection to the SQLite database
        specified by db_file
    :param db_file: database file
    :return: Connection object or None
    """
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except Error as e:
        print(e)

    return conn
 


def create_db(database):
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
    conn = create_connection(database)
    print(conn)
    # create tables
    if conn is not None:
        # create projects table
        create_table(conn, sql_create_projects_table)

        # create tasks table
        create_table(conn, sql_create_tasks_table)
    else:
        print("Error! cannot create the database connection.")



def main():
    database = r"./sqlite.db"
    create_db(database)
   

if __name__ == '__main__':
    main()

