from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy  import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
import requests
import smtplib
import datetime
from flask_gravatar import Gravatar
from functools import wraps

db = SQLAlchemy()
app = Flask(__name__)
lm = LoginManager()
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///posts.db'
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
Bootstrap(app)
ck = CKEditor(app)
lm.init_app(app)
db.init_app(app)
gravatar = Gravatar(app, size=50, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

@lm.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#response = requests.get("https://api.npoint.io/3da2acb942631722d444")
#blog_data = response.json()


class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.name"))
    author = relationship("Users", back_populates="post")
    comment = relationship("Comments", back_populates="parent_post")

class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    post = relationship("BlogPost", back_populates="author")
    comment = relationship("Comments", back_populates="comment_author")


class Comments(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.name"))
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    comment_author = relationship("Users", back_populates="comment")
    parent_post = relationship("BlogPost", back_populates="comment")

with app.app_context():
    db.create_all()

class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    author = StringField("Your Name", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("OK")

class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("LET ME IN")


class CommentForm(FlaskForm):
    body = CKEditorField("Leave your comment here:", validators=[DataRequired()])
    submit = SubmitField("Comment")


def send_mail(name, email, phone, message):
    with smtplib.SMTP("smtp.gmail.com", 587) as connection:
        email_message = f"Subject: New Blog Message\n\nName: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {message}"
        connection.starttls()
        connection.login("noheloleon@gmail.com", "xejgaoaihdzrmyhb")
        connection.sendmail("noheloleon@gmail.com", "nohelp2000@outlook.com", msg=email_message)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function




@app.route("/")
@app.route("/index.html")
def home():
    with app.app_context():
        blog_data = db.session.query(BlogPost).all()
    return render_template("index.html", blog=blog_data, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = generate_password_hash(form.password.data, "pbkdf2:sha256", 8)
        if Users.query.filter_by(email=email).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for("login"))
        new_user = Users(
            name=name,
            email=email,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        password = form.email.data
        if not user:
            flash("Email does not exist")
            return redirect(url_for("login"))
        elif not check_password_hash(user.password, password):
            flash("Incorrect Password")
            return redirect(url_for("login"))
        else:
            login_user(user)
            return redirect(url_for("home"))
    return render_template("login.html", logged_in=current_user.is_authenticated, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/about.html")
def about_page():
    return render_template("/about.html", logged_in=current_user.is_authenticated)


@app.route("/contact.html", methods=["POST", "GET"])
def contact_page():
    if request.method == "POST":
        data = request.form
        send_mail(data["name"], data["email"], data["phone"], data["message"])
        return render_template("/contact.html", msg_sent=True, logged_in=current_user.is_authenticated)
    else:
        return render_template("/contact.html", msg_sent=False, logged_in=current_user.is_authenticated)


@app.route("/post/<int:index>", methods=["GET", "POST"])
def show_post(index):
    form = CommentForm()
    comments = Comments.query.all()
    requested_post = BlogPost.query.get(index)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("post"))

        new_comment = Comments(
            text=form.body.data,
            comment_author=current_user,
            parent_post=requested_post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", index=requested_post.id))

    return render_template("post.html", comments=comments, form=form, post=requested_post, logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def make_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            author=current_user,
            img_url=form.img_url.data,
            date=datetime.datetime.now().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    else:
        return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit_post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.body = edit_form.body.data
        post.author = current_user
        post.img_url = edit_form.img_url.data
        db.session.commit()
        return redirect(url_for(f"show_post", index=post_id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
