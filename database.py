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
        self.con.row_factory = sqlite3.Row
        self.cur = self.con.cursor()

    def create(self):
        CREATE_SCRIPT = '''
        CREATE TABLE Manufacturers (
            id              integer     PRIMARY KEY AUTOINCREMENT   NOT NULL,
            name            varchar     NOT NULL    UNIQUE
        );

        CREATE TABLE Images (
            id              varchar     PRIMARY KEY NOT NULL,
            man_id          integer,
            release_date    datetime    NOT NULL,
            name            varchar     NOT NULL,

            CONSTRAINT fk_mans
                FOREIGN KEY (man_id)
                REFERENCES Manufacturers(id)
                ON DELETE SET NULL
        );

        CREATE TABLE Files (
            id              varchar     PRIMARY KEY NOT NULL,
            scanned         integer     DEFAULT 0
        );

        CREATE TABLE Functions (
            id              integer     PRIMARY KEY AUTOINCREMENT   NOT NULL,
            name            varchar     UNIQUE  NOT NULL,
            vuln_desc       varchar     
        );

        CREATE TABLE Detections (
            func_id         integer     NOT NULL,
            file_id         varchar     NOT NULL,
            call_loc        integer     NOT NULL,

            PRIMARY KEY(func_id, file_id, call_loc),

            CONSTRAINT fk_funcs
                FOREIGN KEY (func_id)
                REFERENCES Functions(id)
                ON DELETE CASCADE,

            CONSTRAINT fk_files
                FOREIGN KEY (file_id)
                REFERENCES Files(id)
                ON DELETE CASCADE
        );

        CREATE TABLE ImageFiles (
            file_id         varchar,
            image_id        varchar NOT NULL,
            path            varchar NOT NULL,

            PRIMARY KEY(file_id, image_id, path)

            CONSTRAINT fk_images
                FOREIGN KEY (image_id)
                REFERENCES Images(id)
                ON DELETE CASCADE,
            
            CONSTRAINT fk_files
                FOREIGN KEY (file_id)
                REFERENCES Files(id)
                ON DELETE SET NULL
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
        self.cur.execute(check_man, [name])
        row = self.cur.fetchone()

        if (row is not None):
            return row['id']
        else:
            new_man = 'INSERT INTO Manufacturers (name) VALUES (?)'
            self.cur.execute(new_man, (name,))
            self.con.commit()
            return self.cur.lastrowid
    
    def newImage(self, signature, man_name, release_date, name):
        man_id = self.getManufacturer(man_name)

        check_image = 'SELECT id FROM Images WHERE id = ?'
        self.cur.execute(check_image, (signature,))
        row = self.cur.fetchone()

        if (row is not None):
            return False
        else:
            new_image = 'INSERT INTO Images (id, man_id, release_date, name) VALUES (?, ?, ?, ?)'
            self.cur.execute(new_image, (signature, man_id, release_date, name))
            self.con.commit()
            return True


    def checkFileScanned(self, signature):
        """
        Takes a file signature and checks if the file exists in the database
        If it doesn't, create an entry for the file and return False
        If it does, return True if scanned value on file == 1
        """
        check_file = 'SELECT * FROM Files WHERE id = ?'
        self.cur.execute(check_file, [signature])
        row = self.cur.fetchone()

        if (row is None):
            new_file = 'INSERT INTO Files (id) VALUES (?)'
            self.cur.execute(new_file, (signature,))
            self.con.commit()
            return False # File didn't exist == not scanned

        return row['scanned'] == 1 # True if scanned, False otherwise


    def checkImageFileScanned(self, image_signature, file_signature, path):
        """
        Creates a new ImageFile entry
        Returns boolean based on if file is marked as scanned already
        Attempts to Add new entry unconditionally
            (this is fine as long as all entries are removed after a failed/repeated scan)
        """

        # get previous file
        file_scanned = self.checkFileScanned(file_signature)

        try:
            new_imagefile = 'INSERT INTO ImageFiles (image_id, file_id, path) VALUES (?, ?, ?)'
            self.cur.execute(new_imagefile, (image_signature, file_signature, path))
            self.con.commit()
        except sqlite3.IntegrityError:
            # since file is marked existing and not scanned, we need scan it yet
            return file_scanned

        return file_scanned

    def setFileScanned(self, file_signature, value=1):
        """
        Sets the file provided as scanned
        """

        update_file = 'UPDATE Files SET scanned = ? WHERE id = ?'
        self.cur.execute(update_file, [value, file_signature])
        self.con.commit()

    def getAllVulnFunctions(self):
        
        select_allfuncs = 'SELECT name FROM Functions'
        self.cur.execute(select_allfuncs)

        return self.cur.fetchall()

    # function is just function name, not including 'sym.imp'
    def addVulnFunction(self, name, desc=None):
        new_func = 'INSERT INTO Functions (name, vuln_desc) VALUES (?, ?)'
        self.cur.execute(new_func, (name, desc))
        self.con.commit()

    def getFuncIdByFullName(self, func):
        get_func = 'SELECT id FROM Functions WHERE name = ?'

        # sym.imp.
        len_to_trim = len('sym.imp.')
        func = func[len_to_trim:]

        self.cur.execute(get_func, [func])

        return self.cur.fetchone()['id']

    def insertDetections(self, file_signature, detections, markscanned=True):
        insert_det = 'INSERT INTO Detections (func_id, file_id, call_loc) VALUES (?, ?, ?)'

        new_detections = []

        for func in detections:
            func_id = self.getFuncIdByFullName(func)
            for location in detections[func]:
                new_detections.append((func_id, file_signature, location))

        self.cur.executemany(insert_det, new_detections)
        self.con.commit()

        if (markscanned):
            self.setFileScanned(file_signature)
        
        
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
        self.con.commit()
        return files_to_scan
    """