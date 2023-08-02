from flask import Flask, render_template, url_for, redirect, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

import json
import os

with open('secrets.json') as f:
    data = json.load(f)


app = Flask(__name__)
bcrypt = Bcrypt(app) #new
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = data['secret_key']

db = SQLAlchemy(app)

#Connecting the login logic to the data base **NEW**
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

#NEW
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/home')
def index():
    return render_template('home.html')

@app.route('/underdev')
def underdev():
    return render_template('under-dev.html')

@app.route('/logout', methods = {'GET', 'POST'})
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

### PRICING/CART PAGE
def cartNumber():
    cart = []
    if 'username' in session:
        user_name = session['username']
        cart = CartItem.query.filter(CartItem.user_name == user_name).all()
    return dict(cart=cart)

app.context_processor(cartNumber) # Update cart number on all pages

items = [
    {'name': 'premium', 
     'price': 4.99,
     'description': 'improve your learning with full access to our features.',
     'tool1': 'flashcard creation',
     'tool2': 'pomodoro study session',
     'tool3': 'calender organization tool',
     'tool4': 'no creaation limits'
    },

    {'name': 'deluxe', 
     'price': 7.99,
     'description': 'enhance your studying with additional tools and no limits.',
     'tool1': 'flashcard creation',
     'tool2': 'pomodoro study session',
     'tool3': 'calender organization tool',
     'tool4': 'schedule/management assistant'
    }
]
class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)

# Renders the pricing 
@app.route('/pricing')
def pricing():
    return render_template('pricing.html', items=items)

# Renders the cart
@app.route('/cart')
def cart():
    user_name = session['username']
    cart = CartItem.query.filter(CartItem.user_name == user_name).all()
    return render_template('cart.html', cart=cart)

# Add to the cart
@app.route('/addcart/<int:item_index>')
def addcart(item_index):
    item = items[item_index]
    user_name = session['username']
    if CartItem.query.filter(CartItem.user_name == user_name).first() is None:
        cart_item = CartItem(name=item['name'], price=item['price'], user_name=user_name)
        db.session.add(cart_item)
        db.session.commit()
        return redirect(url_for('cart'))

    return redirect(url_for('cart'))
# Empty the cart
@app.route('/clear')
def clear():
    CartItem.query.delete()
    db.session.commit()
    return redirect(url_for('cart'))


### FLASHCARD PAGE

# routing for flashcard section of webapp, tied to "tools" in navbar
@app.route('/flash')
def flash():
    # query for full flashcard list, return the query alongside html for webpage
    user_name = session['username']
    topic_list = db.session.query(FlashTopics).filter(FlashTopics.user_name == user_name)
    flash_list = db.session.query(FlashCard).order_by(FlashCard.topic_id).filter(FlashCard.user_name == user_name)

    return render_template('flash.html', flash_list=flash_list, topic_list=topic_list)
    

@app.route('/study')
def study():
    user_name = session['username']
    flash_list = db.session.query(FlashCard).order_by(FlashCard.topic_id).filter(FlashCard.user_name == user_name)
    return render_template('study.html', flash_list=flash_list)


# define schema for FlashCard SQL table
class FlashCard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))
    question = db.Column(db.String(100))
    answer = db.Column(db.String(100))
    rating = db.Column(db.Integer)
    topic_id = db.Column(db.Integer)

class FlashTopics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100))
    topic = db.Column(db.String(100))

@app.route("/add-topic", methods=["POST"])
def add_topic():
    topic= request.form.get("topic")
    user_name = session['username']
    new_topic = FlashTopics(user_name = user_name, topic=topic)
    db.session.add(new_topic)
    db.session.commit()
    return redirect(url_for("flash"))

# using the form from flash.html, make a new entry in the db using the following parameters.
@app.route("/add", methods=["POST"])
def add():
    question= request.form.get("question")
    user_name = session['username']
    answer=request.form.get("answer")
    topic_id=request.form.get("topic_id")
    if topic_id is not None: 
        if len(question) != 0 and len(answer) != 0 and len(topic_id) != 0:
            new_card = FlashCard(question=question, user_name = user_name, answer=answer, rating=0, topic_id=topic_id)
            db.session.add(new_card)
            db.session.commit()
    
    return redirect(url_for("flash"))

# using another form in the flash.html file, using the ID, update the flashcard IF new data is added.
@app.route("/edit", methods=["POST"])
def edit():
    flash_id= request.form.get("id")
    user_name = session['username']
    if flash_id is not None:
        flash = db.session.query(FlashCard).filter(FlashCard.user_name == user_name).filter(FlashCard.id == flash_id).first()
        question2= request.form.get("question2")
        answer2= request.form.get("answer2")
        # if question or answer are blank in the update, they are not modified.
        if len(question2) != 0:
            flash.question = question2
        if len(answer2) != 0:
            flash.answer = answer2
        db.session.commit()
    return redirect(url_for("flash"))

# add to rank value depending on button. Will be used to assess overall understanding of question
@app.route("/update/<int:flash_id>/<int:val>")
def update(flash_id, val):
    flash = db.session.query(FlashCard).filter(FlashCard.id == flash_id).first()
    flash.rating = flash.rating + val
    db.session.commit()
    return redirect(url_for("flash"))

# same long as def update, but for negative values.
@app.route("/update_neg/<int:flash_id>/<int:val>")
def update_neg(flash_id, val):
    flash = db.session.query(FlashCard).filter(FlashCard.id == flash_id).first()
    flash.rating = flash.rating - val
    db.session.commit()
    return redirect(url_for("flash"))

# allows the user to reset the rating of the card to 0
@app.route("/update_res/<int:flash_id>")
def update_res(flash_id):
    flash = db.session.query(FlashCard).filter(FlashCard.id == flash_id).first()
    flash.rating = 0
    db.session.commit()
    return redirect(url_for("flash"))

# allows the user to delete the flashcard from the database
@app.route("/delete/<int:flash_id>")
def delete(flash_id):
    flash = db.session.query(FlashCard).filter(FlashCard.id == flash_id).first()
    db.session.delete(flash)
    db.session.commit()
    return redirect(url_for("flash"))


# Login/signup routes **NEW**

@app.route('/login', methods = {'GET', 'POST'})
def login():
    form = LoginForm()
    mes = " "
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                session['username'] = user.email
                login_user(user)
                return redirect(url_for('index'))
            else:
                mes = "Incorrect password. Please try again."
        else:
            mes = "Incorrect username. Please try again."

    return render_template('login.html', form = form, message = mes)

@app.route('/signup', methods = {'GET', 'POST'})
def signup():

    form = RegisterForm()
    mes = " "
    if form.validate_on_submit():
        user = User.query.filter_by(email = form.email.data).first()
        
        if not user:
            hashed_password = bcrypt.generate_password_hash(form.password.data)
            new_user = User(email = form.email.data, password = hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
            
        else:
            mes = "That username is already in use. Please enter a different one."
            

    return render_template('sign-up.html', form = form, message = mes)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(100), nullable = False, unique = True)
    password = db.Column(db.String(100), nullable = False)

class RegisterForm(FlaskForm):
    email = StringField(validators = [InputRequired(), Length(min = 5, max = 100)], render_kw = {"placeholder": "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 5, max = 100)], render_kw = {"placeholder": "Password"})
    submit = SubmitField("Sign up")

    def validate_username(self, email):
        existing_user_username = User.query.filter_by(email = email.data).first()
        if existing_user_username:
            raise ValidationError("That username is taken")
            

class LoginForm(FlaskForm):
    email = StringField(validators = [InputRequired(), Length(min = 5, max = 100)], render_kw = {"placeholder": "Username"})
    password = PasswordField(validators = [InputRequired(), Length(min = 5, max = 100)], render_kw = {"placeholder": "Password"})
    submit = SubmitField("Login")


# allows you to run app
if __name__ == "__main__":

    if not os.path.exists('site.db'):
        with app.app_context():
            db.create_all()
    
    app.run(debug=False, host = '0.0.0.0')