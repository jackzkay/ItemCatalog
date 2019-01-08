from item_catalog_database import Base, User, Category, Item
from flask import (Flask,
                   jsonify,
                   request,
                   redirect,
                   flash,
                   url_for,
                   abort,
                   g,
                   render_template)
from flask import session as login_session
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, joinedload
from sqlalchemy import create_engine, asc, desc
import random
import string
from flask_httpauth import HTTPBasicAuth
import json

# NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests


app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

auth = HTTPBasicAuth()
engine = create_engine('sqlite:///catalog.db?check_same_thread=False')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


CLIENT_ID = json.loads(open('client_secrets.json',
                       'r').read())['web']['client_id']
APPLICATION_NAME = "ItemCatalog"


@app.route('/login')
def showLogin():
    """showLogin: renders login html

    Args:

    Returns:
        an html file for the login page

    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """gconnect: handles the OAuth login for G+

    Args:

    Returns:
        an html file with a message if the login was successful

    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps("""Current user is already
         connected."""), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += """ " style = "width: 300px; height: 300px;border-radius:
            150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> """
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions


def createUser(login_session):
    """createUser: creates a new user in the User database

    Args:
        login_session: Infrmation about the user

    Returns:
        returns the new users ID

    """
    newUser = User(username=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """getUserInfo: returns the table entry for a user from the user database

    Args:
        user_id (int): A users unique ID

    Returns:
        returns the table entry for a user from the user database

    """
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """getUserID: searches for user ID by users email address

    Args:
        email (str): the email Address

    Returns:
        returns the corresponding user address if applicable

    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

# DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    """gdisconnect: logout for google OAuth

    Args:

    Returns:
        returns if it was successful

    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps("""Failed to revoke token for
        given user.""", 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# API for all categories and their items
@app.route('/catalog.JSON')
def catalogJSON():
    """catalogJSON: queries the data base for the full Item Catalog

    Args:

    Returns:
        returns the full Item Catalog in JSON format

    """
    categories = session.query(Category).options(joinedload
                                                 (Category.items)).all()
    return jsonify(Catalog=[dict(c.serialize, items=[i.serialize
                   for i in c.items])for c in categories])


# API for one category and its items
@app.route('/<string:category_name>.JSON')
def categoryJSON(category_name):
    """categoryJSON: Queries the database for all items of one Category

    Args:
        category_name (str): name of a category
        etc ...

    Returns:
        returns all items for a category in JSON format

    """
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(cat_id=category.id).all()
    return jsonify(Category=dict(category.serialize, items=[i.serialize
                   for i in items]))


# API for one item
@app.route('/<string:category_name>/<string:item_name>.JSON')
def itemJSON(category_name, item_name):
    """itemJSON: queries the database for one specific item of one category

    Args:
        category_name (str): The Category for the item
        item_name (str): the specific item

    Returns:
        returns the item and all its attributes in JSON format

    """
    category = session.query(Category).filter_by(name=category_name).first()
    if category:
        item = session.query(Item).filter_by(title=item_name).first()
        if(category.id == item.cat_id):
            return jsonify(item=item.serialize)
        else:
            return redirect('/')


# show all Categories and latest items, public
@app.route('/')
def showAllCategories():
    """showAllCategories: renders a landing/home page which displays all
                          categories and the latest added items

    Args:


    Returns:
        returns an HTML depended on wether one is logied in

    """
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(desc(Item.id))
    if 'username' not in login_session:
        return render_template('publicCategories.html', items=items,
                               categories=categories)
    else:
        return render_template('categories.html', items=items,
                               categories=categories)


# show all Items of one category, public
@app.route('/<string:category_name>/')
@app.route('/<string:category_name>/items')
def showCategory(category_name):
    """showCategory: renders a all items of one category

    Args:
        category_name (str): the Category name

    Returns:
        returns an HTML depended on wether one is logied in

    """
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).first()
    items = session.query(Item).filter_by(cat_id=category.id)
    if 'username' not in login_session:
        return render_template('publicCategory.html', items=items,
                               categories=categories, category=category)
    else:
        return render_template('category.html', items=items,
                               categories=categories, category=category)


# show an Items in detail, public
@app.route('/<string:category_name>/<string:item_name>/')
def showItem(category_name, item_name):
    """showItem: renders a page with the item description and the possibility
                 to edit/delete if the user is which create the item is
                 logged in

    Args:
        category_name (str): category name
        item_name (str): Item name

    Returns:
        returns an HTML page depending on the user which is logged in

    """
    category = session.query(Category).filter_by(name=category_name).first()
    if category:
        item = session.query(Item).filter_by(title=item_name).first()
        creator = getUserInfo(item.user_id)
        if 'username' not in login_session or creator.id != login_session['user_id']:
            return render_template('publicItem.html', item=item)
        else:
            return render_template('item.html', item=item, category=category)
    else:
        return redirect('/')


# edit Item for any category, only for logged in users, only the creator
@app.route('/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, item_name):
    """editItem: Renders a html page wich allows to edit an Item
                 if the user is which created the item is logged in

    Args:
        category_name (str): category name
        item_name (str): Item name

    Returns:
        returns an HTML page depending on the user which is logged in

    """
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).order_by(asc(Category.name))
    editedItem = session.query(Item).filter_by(title=item_name).first()
    if login_session['user_id'] != editedItem.user_id:
        return """<script>function myFunction() {alert('You are not
            authorized to edit items which you have not created. Please
            create your own items in order to edit items.');}</script>
            <body onload = 'myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            editedItem.title = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['id']:
            editedItem.cat_id = request.form['id']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        return render_template('editItem.html', item=editedItem,
                               categories=categories)


# create new Item for any category, only for logged in users
@app.route('/<string:category_name>/<string:item_name>/delete/',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    """deleteItem: renders a html page wich allows to delete an Item
                 if the user is which created the item is logged in

    Args:
        category_name (str): category name
        item_name (str): Item name

    Returns:
        returns an HTML page depending on the user which is logged in

    """
    category = session.query(Category).filter_by(name=category_name).first()
    itemToDelete = session.query(Item).filter_by(title=item_name).first()
    if 'username' not in login_session:
        return redirect('/login')
    if login_session['user_id'] != itemToDelete.user_id:
        return """<script>function myFunction() {alert('You are not authorized
            to delete this items. Please create your own items in order to
            delete items.');}</script><body onload = 'myFunction()'>"""
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


# create new Item for any category, only for logged in users
@app.route('/catalog/item/new', methods=['GET', 'POST'])
def addItemGeneral():
    """addItemGeneral: renders a html page wich allows to add an Item
                 if the user is logged in

    Args:
        category_name (str): category name

    Returns:
        returns an HTML page depending if a user is logged in

    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Item(title=request.form['title'],
                       user_id=login_session['user_id'],
                       cat_id=request.form['id'],
                       description=request.form['description'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('newItem.html', categories=categories)


# create new Item in certain category, only for logged in users
@app.route('/catalog/<string:category_name>/item/new', methods=['GET', 'POST'])
def addItemCat(category_name):
    """addItemCat: renders a html page wich allows to add an Item
                 if the user is logged in

    Args:
        category_name (str): category name

    Returns:
        returns an HTML page depending if a user is logged in


    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newItem = Item(
            title=request.form['title'], user_id=login_session['user_id'],
            cat_id=request.form['id'], description=request.form['description'])
        session.add(newItem)
        session.commit()
        return redirect(url_for('showAllCategories'))
    else:
        categories = session.query(Category).filter_by(
                                   name=category_name).all()
        return render_template('newItem.html', categories=categories)


# Disconnect
@app.route('/disconnect')
def disconnect():
    """disconnect: manages the logout depending on the OAuth provider

    Args:

    Returns:
        returns to landing page if successful

    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        return redirect(url_for('showAllCategories'))
    else:
        return redirect(url_for('showAllCategories'))


if __name__ == '__main__':
    app.debug = True
    app.config['SECRET_KEY'] = ''.join(random.choice(string.ascii_uppercase +
                                       string.digits) for x in xrange(32))
    app.run(host='0.0.0.0', port=5000)
