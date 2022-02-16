import mysql.connector
from mysql.connector import Error

# Connecting to the database
def create_server_connection(host_name, user_name, user_password, dB_name):
    connection = None
    try:
        connection = mysql.connector.connect(
            host=host_name,
            user=user_name,
            passwd=user_password,
            database=dB_name
        )
        if not dB_name:
            print("MySQL Database connection successful")
        else:
            print("Connected to the {} database".format(dB_name))
    except Error as err:
        print(f"Error: '{err}'")

    return connection

# Execute a query
def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query successful")
    except Error as err:
        print(f"Error: '{err}'")

# Read from database
def read_query(connection, query):
    cursor = connection.cursor()
    result = None
    try:
        cursor.execute(query)
        result = cursor.fetchall()
        return result
    except Error as err:
        print(f"Error: '{err}'")

# main
if __name__ == "__main__":
    connection = create_server_connection("localhost", "root", "", "")
    dB_name = "security_project"
    execute_query(connection, "CREATE DATABASE {}".format(dB_name))
    connection = create_server_connection("localhost", "root", "", dB_name)
    creating_table = """
    CREATE TABLE virus_hashes(
        hash_id INT PRIMARY KEY AUTO_INCREMENT,
        hash VARCHAR(128) NOT NULL UNIQUE
    );"""
    execute_query(connection, creating_table)
    f = open("hash sample.txt", "r")
    for line in f:
        if "#" in line:
            continue
        # print(line.strip())
        execute_query(connection, "INSERT INTO virus_hashes (hash) VALUES ('{}')".format(line.strip()))
    f.close()
    print("Sample hashes are loaded into the database.")