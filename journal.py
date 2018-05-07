import os

from flask import (Flask, render_template, flash, g, redirect, url_for,
                   request, abort)

from flask_bcrypt import check_password_hash
from flask_login import (LoginManager, current_user, login_required,
                             login_user, logout_user)

from peewee import *

import models
import forms

DEBUG = True
PORT = 8000
HOST = '0.0.0.0'

app = Flask(__name__)
app.secret_key = 'superdupersecretkeycanyoubelievethisisrandom'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(userid):
    try:
        return models.User.get(models.User.id == userid)
    except DoesNotExist:
        return None


@app.before_request
def before_request():
    """Connect to the database before each request """
    g.db = models.DATABASE
    g.db.close()
    g.db.connect()
    g.user = current_user


@app.after_request
def after_request(response):
    """Disconnect the database after each request"""
    g.db.close()
    return response


@app.route('/login', methods=('GET', 'POST'))
def login():
    """Login Route"""
    form = forms.LoginForm()
    if form.validate_on_submit():
        try:
            user = models.User.get(models.User.email == form.email.data)
        except DoesNotExist:
            flash("Your email and password do not match.", "error")
        else:
            if check_password_hash(user.password,
                                   form.password.data):
                login_user(user)
                flash("You've been logged in!", "success")
                return redirect(url_for('index'))
            else:
                flash("Your email and password do not match", "error")
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    """Logout Route"""
    logout_user()
    flash("You've been logged out!", "success")
    return redirect(url_for('index'))


@app.route('/register', methods=('GET', 'POST'))
def register():
    """Register Route"""
    form = forms.RegisterForm()
    if form.validate_on_submit():
        try:
            models.User.create_user(
                email=form.email.data,
                password=form.password.data
            )
        except ValueError:
            flash("Account for {} already exists".format(form.email.data))
        else:
            flash("Account for {} created".format(form.email.data))
            return redirect(url_for('index'))
    return render_template('register.html', form=form)


@app.route('/')
@app.route('/<tag>')
def index(tag=None):
    """Index Route"""
    try:
        if tag:
            entries = (models.Entry.select()
                .join(models.Tag)
                .where(
                    (models.Entry.user == g.user._get_current_object()) &
                    (models.Tag.tag == tag)
                    )
                    .order_by(models.Entry.date.desc())
                    )
        else:
            entries = (models.Entry.select()
                .where(models.Entry.user == g.user._get_current_object())
                .order_by(models.Entry.date.desc())
            )
    except AttributeError:
        entries = None
    else:
        tags = models.Tag.select().group_by(models.Tag.tag)
        return render_template('index.html', entries=entries, tags=tags)


@app.route('/new', methods=('GET', 'POST'))
@login_required
def new_entry():
    """Entry Route"""
    form = forms.EntryForm()
    if form.validate_on_submit():
        try:
            models.Entry.create(
                user=g.user._get_current_object(),
                title=form.title.data.strip(),
                date=form.date.data,
                time_spent=form.time_spent.data.strip(),
                what_i_learned=form.what_i_learned.data.strip(),
                resources_to_remember=form.resources_to_remember.data.strip()
                )
            tags = form.tags.data.strip().split(" ")
            for tag in tags:
                models.Tag.create(
                    entry=models.Entry.get(models.Entry.title ==
                        form.title.data.strip()),
                    tag=tag
                )
        except IntegrityError:
            flash("Title must be unique.")
            return render_template('new.html', form=form)
        else:
            flash("Journal entry created!")
            return redirect(url_for('index'))
    else:
        return render_template('new.html', form=form)



@app.route('/detail/<slug>')
@login_required
def detail(slug):
    try:
        entries = current_user.get_entries()
        for result in entries:
            if result.slug == slug:
                entry = result
        tags = models.Tag.select().where(models.Tag.entry == entry)
    except models.Entry.DoesNotExist:
        abort(404)
    else:
        return render_template(
            'detail.html',
            entry=entry,
            resources=entry.resources_to_remember.splitlines(),
            tags=tags
        )


@app.route('/delete/<slug>')
@login_required
def delete_entry(slug):
    try:
        # Get the entry based on its slug hybrid_property.
        entries = current_user.get_entries()
        for result in entries:
            if result.slug == slug:
                entry = result

        # Delete any tags associated with the entry.
        delete_tags_query = models.Tag.delete().where(models.Tag.entry == entry)
        delete_tags_query.execute()

        # Delete the entry.
        entry.delete_instance()
    except models.Entry.DoesNotExist:
        abort(404)
    else:
        flash("Journal entry deleted!")
        return redirect(url_for('index'))


@app.route('/edit/<slug>', methods=('GET', 'POST'))
@login_required
def edit_entry(slug):
    # Get the entry based on its slug hybrid_property.
    entries = current_user.get_entries()
    for result in entries:
        if result.slug == slug:
            entry = result
    form = forms.EntryForm()
    tags = models.Tag.select().where(models.Tag.entry == entry)

    if form.validate_on_submit():
        try:
            # update the entry
            entry.user=g.user._get_current_object()
            entry.title=form.title.data.strip()
            entry.date=form.date.data
            entry.time_spent=form.time_spent.data.strip()
            entry.what_i_learned=form.what_i_learned.data.strip()
            entry.resources_to_remember=form.resources_to_remember.data.strip()
            entry.save()

            # delete old tags
            delete_tags = models.Tag.delete().where(models.Tag.entry == entry)
            delete_tags.execute()

            # write new tags
            tags = form.tags.data.strip().split(" ")
            for tag in tags:
                models.Tag.create(
                    entry=models.Entry.get(
                        models.Entry.title == form.title.data.strip()
                    ),
                    tag=tag
                )

        except IntegrityError:
            flash("Title must be unique.")
            return render_template('edit.html', form=form,
                                    tags=tags, entry=entry)
        else:
            flash("Journal entry edited!")
            return redirect(url_for('index'))
    else:
        return render_template('edit.html', form=form, tags=tags, entry=entry)


if __name__ == '__main__':
    models.initialize()
    try:
        with models.DATABASE.transaction() as txn:
            models.User.create_user(
                email='example@test.com',
                password='password'
            )
        print("user: example@test.com, password: 'password' created.")
        models.DATABASE.close()
    except ValueError:
        admin = models.User.get(models.User.email ==
                                'example@test.com')
        print("user example@test.com already exists!")
    app.run(debug=DEBUG, host=HOST, port=PORT)
