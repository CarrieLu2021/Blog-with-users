from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from flask_ckeditor import CKEditorField
from wtforms.validators import DataRequired, Length, Email, URL


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired(), Length(10)])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class CommentForm(FlaskForm):
    text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message="Invalid Email, please try again.")])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign me up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email(message="Invalid Email, please try again.")])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField(label="Let me in!")



