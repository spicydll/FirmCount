import sqlite3

class iotDB:

    def __init__(self):
        self.database = 'iotcount.db'
        self.con = sqlite3.connect(self.database)
        self.cur = self.con.cursor()

    def create(self):
        CREATE_SCRIPT = '''
        CREATE TABLE Manufacturers (
            id integer PRIMARY KEY AUTOINCREMENT,
            name varchar
        );

        CREATE TABLE Images (
            id blob,
            man_id int,
            release_date datetime,
            name varchar
        );

        CREATE TABLE Files (
            id blob
        );

        CREATE TABLE Functions (
            id integer PRIMARY KEY AUTOINCREMENT,
            name varchar,
            vuln_desc varchar
        );

        CREATE TABLE Detections (
            func_id integer,
            file_id blob,
            call_ref blob
        );

        CREATE TABLE ImageFiles (
            file_id blob,
            image_id blob,
            path varchar
        );
        '''

        self.cur.executescript(CREATE_SCRIPT)
        self.con.commit()

    def destroy(self):
        DROP_SCRIPT = '''
        DROP TABLE IF EXISTS Manufacturers;

        DROP TABLE IF EXISTS Images;

        DROP TABLE IF EXISTS Files;

        DROP TABLE IF EXISTS Functions;

        DROP TABLE IF EXISTS Detections;

        DROP TABLE IF EXISTS ImageFiles;
        '''

        self.cur.executescript(DROP_SCRIPT)
        self.con.commit()

    
    def reinit(self):
        self.destroy()
        self.create()

    def getManufacturer(self, name):
        check_man = 'SELECT id FROM Manufacturers WHERE name = ?'
        self.cur.execute(check_man, name)
        row = self.cur.fetchone()

        if (row is not None):
            return row['id']
        else:
            new_man = 'INSERT INTO Manufacturers (name) VALUES (?)'
            self.cur.execute(new_man, name)
            self.cur.commit()
            return self.cur.lastrowid
    
    def newImage(self, signature, man_name, release_date, name):
        man_id = self.getManufacturer(man_name)

        check_image = 'SELECT id FROM Images WHERE id = ?'
        self.cur.execute(check_image, signature)
        row = self.cur.fetchone()

        if (row is not None):
            return False
        else:
            new_image = 'INSERT INTO Images (id, man_id, release_date, name) VALUES (?, ?, ?, ?)'
            self.cur.execute(new_image, signature, man_id, release_date, name)
            self.cur.commit()
            return True


    def getFile(self, signature):
        check_file = 'SELECT id FROM Files WHERE id = ?'
        self.cur.execute(check_file, signature)
        row = self.cur.fetchone()

        if (row is not None):
            return True
        else 
            new_file = 'INSERT INTO Files VALUES (?)'
            self.cur.execute(new_file, signature)
            self.cur.commit()
            return False
