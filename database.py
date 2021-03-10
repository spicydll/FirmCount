import sqlite3

CREATE_SCRIPT = '''
CREATE TABLE Manufacturers (
	id integer PRIMARY KEY AUTOINCREMENT,
	name varchar
);

CREATE TABLE Images (
	id blob,
	man_id blob,
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
	name varchar
);
'''

DROP_SCRIPT = '''
DROP TABLE IF EXISTS Manufacturers;

DROP TABLE IF EXISTS Images;

DROP TABLE IF EXISTS Files;

DROP TABLE IF EXISTS Functions;

DROP TABLE IF EXISTS Detections;

DROP TABLE IF EXISTS ImageFiles;
'''