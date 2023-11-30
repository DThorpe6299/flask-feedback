from flask import Flask, render_template, redirect, session, flash
from flask_debugtoolbar import DebugToolbarExtension
from models import connect_db, db, User, Feedback
from forms import RegisterForm, LoginForm, FeedbackForm
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///auth_exercise"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
app.config["SECRET_KEY"] = "abc123"
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False


connect_db(app)

toolbar = DebugToolbarExtension(app)

@app.route('/')
def home_page():
    return redirect('/redirect')

@app.route('/register', methods=["GET", "POST"])
def register_user():
    """Register user: produce form & handle form submission."""
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        
        user = User(username=name, password=password, email=email, first_name=first_name, last_name=last_name)
        db.session.add(user)
        db.session.commit()
        return redirect("/secret")
    else:
        return render_template("register.html", form=form)
    
@app.route('/login', methods=["GET", "POST"])
def login():
    """Produce login form; handle login."""
    form = LoginForm()
    if form.validate_on_submit():
        username=form.username.data
        password=form.password.data
        #authenticate will return a user or False
        user=User.authenticate(username, password)
        if user:
            session['username']=user.username #keep logged in
            return redirect('/secret')
    else:
        return render_template('login.html', form=form)
    
@app.route('/secret')
def secret():
    """Example hidden page fro logged-in users only."""
    if 'user_id' not in session:
        flash("You must be logged in to view!")
        return redirect('/')
    else:
        return render_template('secret.html')

@app.route('/logout')
def logout():
    """Logs user out and redirects to homepage."""
    session.pop('username')
    return redirect('/')

@app.route('/users/<username>')
def show_user(username):
    """Show information about the given user.
    Show all of the feedback that the user has given.
    For each piece of feedback, display with a link to a form to edit the feedback and a button to delete the feedback."""
    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    user=User.query.filter_by(username=username).first()
    feedbacks = Feedback.query.filter_by(username=username).all()
    return render_template('feedbacks.html', user=user, feedbacks=feedbacks)
    
@app.route('/users/<username>/delete')
def user_delete(username):
    """Remove the user from the database and make sure to also delete all of their feedback. Clear any user information in the session and redirect to /."""

    if 'username' not in session:
        flash("Please login first!", "danger")
        return redirect('/login')
    username = session['username']
    user=User.query.filter_by(username=username).first()

    if user:
        for feedback in user.feedbacks:
            db.session.delete(feedback)
        
        db.session.delete(user)
        db.session.commit()
    return redirect('/')


@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
def add_feedback(username):
    """Display a form to add feedback Make sure that only the user who is logged in can see this form. Add a new piece of feedback and redirect to /users/<username>."""
    if "username" not in session:
        flash("Please login first!", "danger")
        return redirect('/')

    logged_in_username = session['username']
    if username != logged_in_username:
        flash("You can only add feedback to your own profile!", "danger")
        return redirect('/')

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found!", "danger")
        return redirect('/')

    form = FeedbackForm()
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data

        new_feedback = Feedback(title=title, content=content, username=username)
        db.session.add(new_feedback)
        db.session.commit()
        flash("Feedback added successfully!", "success")
        return redirect(f'/users/{username}')

    return render_template('feedback_form.html', form=form, user=user)

@app.route('/feedback/<int:feedback_id>/update', methods=['GET', 'POST'])
def update_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    if 'username' not in session or session['username'] != feedback.username:
        flash("You can only update your own feedback!", "danger")
        return redirect('/')

    form = FeedbackForm(obj=feedback)
    if form.validate_on_submit():
        form.populate_obj(feedback)
        db.session.commit()
        flash("Feedback updated successfully!", "success")
        return redirect(f'/users/{feedback.username}')

    return render_template('feedback_update.html', form=form, feedback=feedback)

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)

    if 'username' not in session or session['username'] != feedback.username:
        flash("You can only delete your own feedback!", "danger")
        return redirect('/')

    db.session.delete(feedback)
    db.session.commit()
    flash("Feedback deleted successfully!", "success")
    return redirect(f'/users/{feedback.username}')