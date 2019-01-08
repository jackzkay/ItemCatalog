from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from item_catalog_database import Category, Base, Item, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(username="Test", email="Test@test.com",
             picture='https://someurl.com/picture.png')
session.add(User1)
session.commit()

# Menu for UrbanBurger
category1 = Category(user_id=1, name="Clubs")

session.add(category1)
session.commit()

category2 = Category(user_id=1, name="Stadiums")

session.add(category2)
session.commit()

category3 = Category(user_id=1, name="Equipment")

session.add(category3)
session.commit()

category4 = Category(user_id=1, name="Leagues")

session.add(category4)
session.commit()

item1 = Item(user_id=1, title="Stuttgarter Kickers", description="A small club in Stuttgarts quarter Degerloch",
                     cat_id=1)

session.add(item1)
session.commit()


item2 = Item(user_id=1, title="Stadion auf der Waldau", description="A very old Stadium which can carry 10t spectators",
                     cat_id=2)

session.add(item2)
session.commit()

item3 = Item(user_id=1, title="Germania", description="Subber sach",
                     cat_id=1)

session.add(item3)
session.commit()

print "added some items and Categories!"