import datetime
import re

from flask.ext.login import UserMixin
from flask.ext.bcrypt import generate_password_hash
from peewee import *
from slugify import slugify
from sqlalchemy.ext.hybrid import hybrid_property
from unicodedata import normalize

DATABASE = SqliteDatabase('journal_entries.db')


class User(UserMixin, Model):
    """User Model"""
    email = CharField(unique=True)
    password = CharField(max_length=100)

    class Meta:
        database = DATABASE

    @classmethod
    def create_user(cls, email, password):
        try:
            with DATABASE.transaction():
                cls.create(
                    email=email,
                    password=generate_password_hash(password))
        except IntegrityError:
            raise ValueError("User already exists")

    def get_entries(self):
        return Entry.select().where(Entry.user == self)


class Entry(Model):
    """Journal Entry Model"""
    user = ForeignKeyField(User, related_name='entries')
    title = CharField(unique=True)
    date = DateTimeField(default=datetime.datetime.now)
    time_spent = CharField()
    what_i_learned = TextField()
    resources_to_remember = TextField()

    class Meta:
        database = DATABASE
        only_save_dirty = True

    def tags(self):
        return models.Tag.select().where(models.Tag.entry == entry)

    @hybrid_property
    def slug(self):
        return slugify(str(self.title))


class Tag(Model):
    """Tag Model"""
    entry = ForeignKeyField(
        Entry,
        related_name='tags'
    )
    tag = CharField()

    class Meta:
        database = DATABASE


def initialize():
    """Create the database and the tables if they don't exist"""
    with DATABASE.transaction():
        DATABASE.create_tables([User, Entry, Tag], safe=True)
