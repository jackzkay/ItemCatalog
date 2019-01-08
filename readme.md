# Item Catalog Project
Second project of the Full Stack Developer Nanodegree. Student Name: Jakob Klein

## installation

this code is written for Python and uses the following modules
```
flask
sqlalchemy
flask_httpauth
```

### Database Setup

The database contains 3 tables, Users, Categories and Items. To create the database and add some categories and items run
```
python item_catalog_database.py
python addsomeItems.py 
```

## Usage

start the web server with
```
python item_catalog_n.py
```

One can access the landing page with http://localhost:5000/


## Accessing the JSON API

In order to get the full list of Categories and their items, query:

```
http://localhost:5000/catalog.JSON
```

If all Items of one category are needed, query:
```
http://localhost:5000/<Category_Name>.JSON
```
E.g.
```
http://localhost:5000/Clubs.JSON
```

If only the information of one single item is needed, query:
```
http://localhost:5000/<Category_Name>/<Item_Name>.JSON
```
E.g.
```
http://localhost:5000/Clubs/Germania.JSON
```


