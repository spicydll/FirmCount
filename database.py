import sqlite3

"""
NOTES:

This code assumes a few things about the files we are scanning
1. Two files that produce the same cryptographic signature are exactly the same
2. Two files that are exactly the same have the same call structure
3. 
"""

class iotDB:

    def __init__(self):
        self.database = 'iotcount.db'
        self.con = sqlite3.connect(self.database)
        self.cur = self.con.cursor()

    def create(self):
        CREATE_SCRIPT = '''
        CREATE TABLE Manufacturers (
            id              integer     PRIMARY KEY AUTOINCREMENT   NOT NULL,
            name            varchar     NOT NULL    UNIQUE
        );

        CREATE TABLE Images (
            id              varchar     PRIMARY KEY NOT NULL,
            man_id          integer     NOT NULL,
            release_date    datetime    NOT NULL,
            name            varchar     NOT NULL
        );

        CREATE TABLE Files (
            id              varchar     PRIMARY KEY NOT NULL
            scanned         integer     DEFAULT 0
        );

        CREATE TABLE Functions (
            id              integer     PRIMARY KEY AUTOINCREMENT   NOT NULL,
            name            varchar     UNIQUE  NOT NULL,
            vuln_desc       varchar     
        );

        CREATE TABLE Detections (
            func_id         integer     PRIMARY KEY NOT NULL,
            file_id         varchar     PRIMARY KEY NOT NULL,
            call_loc        blob        PRIMARY KEY NOT NULL
        );

        CREATE TABLE ImageFiles (
            file_id         varchar     PRIMARY KEY NOT NULL,
            image_id        varchar     PRIMARY KEY NOT NULL,
            path            varchar     PRIMARY KEY NOT NULL
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

    def close(self):
        self.cur.close()
        self.con.close()

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
            self.cur.execute(new_image, (signature, man_id, release_date, name))
            self.cur.commit()
            return True


    def checkFileScanned(self, signature):
        """
        Takes a file signature and checks if the file exists in the database
        If it doesn't, create an entry for the file and return False
        If it does, return True if scanned value on file == 1
        """
        check_file = 'SELECT * FROM Files WHERE id = ?'
        self.cur.execute(check_file, signature)
        row = self.cur.fetchone()

        if (row is None):
            new_file = 'INSERT INTO Files (id) VALUES (?)'
            self.cur.execute(new_file, signature)
            self.cur.commit()
            return False # File didn't exist == not scanned

        return row['scanned'] == 1 # True if scanned, False otherwise


    def checkImageFileScanned(self, image_signature, file_signature, path):
        """
        Creates a new ImageFile entry
        Returns boolean based on if file is marked as scanned already
        Does NOT check if file already exists
        """

        # get previous file
        file_scanned = self.checkFileScanned(file_signature)

        new_imagefile = 'INSERT INTO ImageFiles (image_id, file_id, path) VALUES (?, ?, ?)'
        self.cur.execute(new_imagefile, (image_signature, file_signature, path))
        self.cur.commit()

        return file_scanned

    """
    def getFiles(self, signatures):
        #""
        Takes an array of 
        #""

        check_file = 'SELECT id FROM Files WHERE id IN ({0})'.format(', '.join('?' for _ in signatures))

        self.cur.execute(check_file, signatures)
        scanned_files = self.cur.fetchall()

        for file in signatures:
            if
        
        new_file = 'INSERT INTO Files VALUES (?)'
        self.cur.executemany(new_file, files_to_scan)
        self.cur.commit()
        return files_to_scan
    """