import sqlite3

HPDATABASE = 'HPRelsNotesDb.db'

def db_read_onecol(read_command):
    """Function to read one column from a HPRelsNotesDb table."""

    con = sqlite3.connect(HPDATABASE)
    cursorObj = con.cursor()

    result = []

    cursorObj.execute(read_command)
    rows = cursorObj.fetchall()
    for row in rows:
       result.append(row[0])

    cursorObj.close()

    return result

def db_read_twocol(read_command):
    """Function to read two columns from a HPRelsNotesDb table."""

    con = sqlite3.connect(HPDATABASE)
    cursorObj = con.cursor()

    result = []

    cursorObj.execute(read_command)
    rows = cursorObj.fetchall()
    for row in rows:
       result.append([row[0], row[1]])

    cursorObj.close()

    return result

def db_write(write_command):
    """Function to write to HPRelsNotesDb table."""

    con = sqlite3.connect(HPDATABASE)
    cursorObj = con.cursor()

    cursorObj.execute(write_command)
    con.commit()
    cursorObj.close()

    return None
