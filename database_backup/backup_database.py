import mysql.connector
import os
import datetime

# Database credentials
DB_HOST = 'mysql'
DB_USER = 'root'
DB_PASSWORD = 'password'
DB_NAME = 'company'

# Backup directory
BACKUP_DIR = '.'

# Get current date and time for the backup file name
backup_file = os.path.join(BACKUP_DIR, f"{DB_NAME}_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.sql")

def backup_database():
    try:
        # Connect to the database
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

        cursor = connection.cursor()

        # Fetch all table names
        cursor.execute("SHOW TABLES;")
        tables = cursor.fetchall()

        with open(backup_file, 'w') as f:
            for (table_name,) in tables:
                # Write the CREATE TABLE statement
                cursor.execute(f"SHOW CREATE TABLE {table_name};")
                create_table_stmt = cursor.fetchone()[1]
                f.write(f"{create_table_stmt};\n\n")

                # Write the INSERT statements
                cursor.execute(f"SELECT * FROM {table_name};")
                rows = cursor.fetchall()
                for row in rows:
                    formatted_values = [
                        f'"{value}"' if isinstance(value, (str, datetime.date)) else str(value) 
                        for value in row
                    ]
                    insert_stmt = f"INSERT INTO {table_name} VALUES ({', '.join(formatted_values)});"
                    f.write(insert_stmt + "\n")
                
                f.write("\n")

        print(f"Backup successful! Saved to {backup_file}")

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

if __name__ == "__main__":
    backup_database()
