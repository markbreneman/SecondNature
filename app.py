# -*- encoding: utf-8 -*-
import os,sys,re,datetime
# import re
# import datetime

from flask import Flask, session, request, url_for, escape, render_template, json, jsonify, flash, redirect, abort
from werkzeug import secure_filename
# from unidecode import unidecode #unidecode is a slug helper module to create page slugs
from boto.s3.connection import S3Connection
from boto.s3.key import Key

#import all of mongoengine
from flask.ext.mongoengine import mongoengine


# Flask-Login 
from flask.ext.login import (LoginManager, current_user, login_required,
                            login_user, logout_user, UserMixin, AnonymousUser,
                            confirm_login, fresh_login_required)

# Library
from flaskext.bcrypt import Bcrypt

#custom user library - maps User object to User model
from libs.user import *

#import data models
import models

#import boto - for AWS connection
import boto

#Python Image Library
import StringIO

#___________CONFIG_____________#
app = Flask(__name__) #Create the Flask App
app.debug = True
app.secret_key = os.environ.get('SECRET_KEY') # SECRET_KEY=...... inside .env
# app.config['TRAP_BAD_REQUEST_ERRORS'] = True

# app.config['CSRF_ENABLED'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 # 16 megabyte file upload

# Flask BCrypt will be used to salt the user password
flask_bcrypt = Bcrypt(app)

#mongolab connection
# uses .env file to get connection string
# using a remote db get connection string from heroku config
# 	using a local mongodb put this in .env
#   MONGOLAB_URI=mongodb://localhost:27017/secondnatureproject
mongoengine.connect('userdemo', host=os.environ.get('MONGOLAB_URI'))
app.logger.debug("Connecting to MongoLabs")

# Login management defined
# reference http://packages.python.org/Flask-Login/#configuring-your-application
login_manager = LoginManager()
login_manager.anonymous_user = Anonymous
login_manager.login_view = "login"
login_manager.login_message = u"Please log in to access this page."
login_manager.refresh_view = "reauth"

# Flask-Login requires a 'user_loader' callback 
# This method will called with each Flask route request automatically
# When this callback runs, it will populate the User object, current_user
# reference http://packages.python.org/Flask-Login/#how-it-works
@login_manager.user_loader
def load_user(id):
	if id is None:
		redirect('/login')

	user = User()
	user.get_by_id(id)
	if user.is_active():
		return user
	else:
		return None

# connect the login manager to the main Flask app
login_manager.setup_app(app)

# Amazon S3 file extensions
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

# main route - display recent posts by all users
@app.route('/')
def index():
	# get requested user's content
	user_content = models.Content.objects
	
	# prepare registration form		
	registerForm = models.SignupForm(request.form)

	app.logger.info(request.form)

	# prepare login form
	loginForm = models.LoginForm(request.form)

	# prepare the template data dictionary
	templateData = {
		'current_user' : current_user,
		'user_content'  : user_content,
		'form' : registerForm,
		'login' :loginForm,
		'users' : models.User.objects()
	}
	
	
	app.logger.debug(current_user)

	return render_template('home.html', **templateData)


#
# Display all the posts for a given user.
#
@app.route('/users/<username>')
def user(username):

	# Does requested username exists, 404 if not
	try:
		user = models.User.objects.get(username=username)

	except Exception:
		e = sys.exc_info()
		app.logger.error(e)
		abort(404)

	# get content that is linked to user, 
	user_content = models.Content.objects(user=user)

	# prepare the template data dictionary
	templateData = {
		'user' : user,
		'current_user' : current_user,
		'user_content'  : user_content,
		'users' : models.User.objects()
	}

	return render_template('user_content.html', **templateData)


#
# Register new user
#
@app.route("/register", methods=['GET','POST'])
def register():
	
	# prepare registration form 
	registerForm = models.SignupForm(request.form)
	app.logger.info(request.form)

	if request.method == 'POST' and registerForm.validate():
		email = request.form['email']
		username = request.form['username']

		# generate password hash
		password_hash = flask_bcrypt.generate_password_hash(request.form['password'])
		
		# prepare User
		user = User(username=username, email=email, password=password_hash)
	
		# save new user, but there might be exceptions (uniqueness of email and/or username)
		try:
			user.save()	
			if login_user(user, remember="no"):
				flash("Logged in!")
				#JOHN SCHIMMEL: Wwhat does the request.args.get do?
				return redirect(request.args.get("next") or '/welcome')
			else:
				flash("unable to log you in")

		# got an error, most likely a uniqueness error
		except mongoengine.queryset.NotUniqueError:
			e = sys.exc_info()
			exception, error, obj = e
			
			app.logger.error(e)
			app.logger.error(error)
			app.logger.error(type(error))

			# uniqueness error was raised. tell user (via flash messaging) which error they need to fix.
			if str(error).find("email") > -1:			
				flash("Email submitted is already registered.","register")
	
			elif str(error).find("username") > -1:
				flash("Username is already registered. Pick another.","register")

			app.logger.error(error)	

	# prepare registration form			
	templateData = {
		'form' : registerForm
	}
	
	return render_template("/auth/register.html", **templateData)

	
# Login route - will display login form and receive POST to authenticate a user
@app.route("/login", methods=["GET", "POST"])
def login():

	# get the login and registration forms
	loginForm = models.LoginForm(request.form)
	
	# is user trying to log in?
	# 
	if request.method == "POST" and 'email' in request.form:
		email = request.form["email"]

		user = User().get_by_email_w_password(email)
		
		# if user in database and password hash match then log in.
	  	if user and flask_bcrypt.check_password_hash(user.password,request.form["password"]) and user.is_active():
			remember = request.form.get("remember", "no") == "yes"

			if login_user(user, remember=remember):
				flash("Logged in!")
				return redirect(request.args.get("next") or '/photostream')
			else:

				flash("unable to log you in","login")
	
		else:
			flash("Incorrect email and password submission","login")
			return redirect("/login")

	else:

		templateData = {
			'form' : loginForm
		}

		return render_template('/auth/login.html', **templateData)


@app.route('/admin', methods=['GET','POST'])
@login_required
def admin_main():

	projectForm = models.project_form(request.form)
	uuidForm=models.uuid_form(request.form)	

	templateData = {
		'allContent' : models.Content.objects(user=current_user.id),
		'current_user' : current_user,
		'project_form' : projectForm,
		'uuid_form':uuidForm
	}

	return render_template('admin.html', **templateData)
		
@app.route('/admin/<content_id>', methods=['GET','POST'])
@login_required
def admin_edit_post(content_id):

	# get the content requested
	contentData = models.Content.objects.get(id=content_id)

	# if contentData exists AND is owned by current_user then continue
	if contentData and contentData.user.id == current_user.id:

		# create the content form, populate with contentData
		contentForm = models.content_form(request.form, obj=contentData)

		if request.method=="POST" and contentForm.validate():
			app.logger.debug(request.form)
			
			contentData.title = request.form.get('title')
			contentData.content = request.form.get('content')

			
			try:
				contentData.save()

			except:
				e = sys.exc_info()
				app.logger.error(e)
			
			flash("Post was updated successfully.")
			return redirect('/admin/%s' % contentData.id)

		else:
			templateData = {
				'allContent' : models.Content.objects(user=current_user.id),
				'current_user' : current_user,
				'form' : contentForm,
				'formType' : 'Update'
			}
		
		return render_template('admin.html', **templateData)

	# current user does not own requested content
	elif contentData.user.id != current_user.id:
 
		flash("Log in to edit this content.","login")
		return redirect("/login")
	else:

		abort(404)
	

@app.route("/reauth", methods=["GET", "POST"])
@login_required
def reauth():
    if request.method == "POST":
        confirm_login()
        flash(u"Reauthenticated.")
        return redirect(request.args.get("next") or url_for("index"))
    
    templateData = {}
    return render_template("/auth/reauth.html", **templateData)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logged out.")
    return redirect(url_for("index"))

@app.route("/requirements", methods=["GET"])
def requirements():

	# prepare login form
	loginForm = models.LoginForm(request.form)

	templateData = {
		'form' :loginForm,
	}

	return render_template('requirements.html', **templateData)
	

@app.route("/contact", methods=["GET"])
def contact():

	# prepare login form
	loginForm = models.LoginForm(request.form)

	templateData = {
		'form' :loginForm,
	}
	return render_template('contact.html', **templateData)

@app.route("/welcome", methods=["GET"])
def welcome():

	# get requested user's content
	user_content = models.Content.objects
	
	# prepare registration form		
	donateForm = models.DonateForm(request.form)
	app.logger.info(request.form)
	
	# prepare the template data dictionary
	templateData = {
		'current_user' : current_user,
		'user_content'  : user_content,
		'form' : donateForm,
		'users' : models.User.objects()
	}
	
	return render_template('welcome.html', **templateData)

@app.route("/donate", methods=["GET"])
def donate():

	# get requested user's content
	user_content = models.Content.objects
	
	# prepare donation form		
	donateForm = models.DonateForm(request.form)
	app.logger.info(request.form)
	
	# prepare the template data dictionary
	templateData = {
		'current_user' : current_user,
		'user_content'  : user_content,
		'form' : donateForm,
		'users' : models.User.objects()
	}
	
	return render_template('donate.html', **templateData)

@app.route("/donated", methods=["POST"])
def donated():

	donateForm = models.DonateForm(request.form)
	userloggedin=current_user.get()

	address = request.form['address']
	address2 = request.form['address2']
	city = request.form['city']
	state = request.form['state']
	zipcode = request.form['zipcode']
	

	app.logger.info(request.form)

	# if request.method == 'POST' and donateForm.validate():
	if request.method == 'POST':
		userloggedin.address=address
		userloggedin.address2=address2
		userloggedin.city=city
		userloggedin.state=state
		userloggedin.zipcode=zipcode
		userloggedin.donated=True
		userloggedin.save()
	
	else:
			flash("All Fields Required","donate")
			return redirect("/donate")

	# prepare the template data dictionary
	templateData = {
		'current_user' : current_user,
		'users' : user
	}

	return render_template('donated.html', **templateData)


@app.route("/photostream", methods=["GET"])
def photostream():

	# get requested user's content
	user_content = models.Content.objects

	#Connecting to S3
	s3conn = boto.connect_s3(os.environ.get('AWS_ACCESS_KEY_ID'),os.environ.get('AWS_SECRET_ACCESS_KEY'))
	app.logger.debug("Connecting to AWS")
	bucket = s3conn.get_bucket(os.environ.get('AWS_BUCKET')) # bucket name defined in .env

	#Variable for Bucket Parsing
	photoList = []
	splitFileName = []
	uuidlist = []
	projects={}

	#List all my file in the bucket and create a photoList
	for key in bucket.list():
	    photoList.append(key.name.encode('utf-8'))
	    key.set_acl('public-read-write')

	#Parse the PhotoList
	for photo in photoList:
		#Split the string
	    splitFileName = photo.split("_",1)
	    #splitfilename[0] is uuid
	    uuid=splitFileName[0]
	    uuidlist.append(splitFileName[0])
	    #splitfilename[1] is timestamp
	    timestamp=splitFileName[1].split(".",1)[0]
	    
	    if uuid in projects:
	    	projects[uuid].append(timestamp)
	    else: 
	    	projects[uuid]=[timestamp]

	app.logger.debug(projects) 
	app.logger.debug(photoList)
	# app.logger.debug(projectList)
	# app.logger.debug(theList)

	   
	# prepare the template data dictionary
	templateData = {
		'current_user' : current_user,
		'user_content'  : user_content,		
		'users' : models.User.objects(),
		'photolist':photoList,
		# 'projectlist': projectList

	}
	
	return render_template('photostream.html', **templateData)

@app.route("/upload", methods=['GET','POST'])
def upload():

	# get Idea form from models.py
	photo_upload_form = models.photo_upload_form(request.form)

	# if form was submitted and it is valid...
	# if request.method == "POST" and photo_upload_form.validate():
	if request.method == "POST":

		uploaded_file = request.files['fileupload']
		# app.logger.info(file)
		# app.logger.info(file.mimetype)
		# app.logger.info(dir(file))

		# Uploading is fun
		# 1 - Generate a file name with the datetime prefixing filename
		# 2 - Connect to s3
		# 3 - Get the s3 bucket, put the file
		# 4 - After saving to s3, save data to database

		# if uploaded_file  and allowed_file(uploaded_file.filename)
		
		if uploaded_file:
			# create filename, prefixed with datetime
			now = datetime.datetime.now()
			filename = now.strftime('%Y%m%d%H%M%s') + "-" + secure_filename(uploaded_file.filename)
			# thumb_filename = now.strftime('%Y%m%d%H%M%s') + "-" + secure_filename(uploaded_file.filename)

			# connect to s3
			s3conn = boto.connect_s3(os.environ.get('AWS_ACCESS_KEY_ID'),os.environ.get('AWS_SECRET_ACCESS_KEY'))

			# open s3 bucket, create new Key/file
			# set the mimetype, content and access control
			b = s3conn.get_bucket(os.environ.get('AWS_BUCKET')) # bucket name defined in .env
			k = b.new_key(b)
			k.key = filename
			k.set_metadata("Content-Type", uploaded_file.mimetype)
			k.set_contents_from_string(uploaded_file.stream.read())
			k.make_public()

			# save information to MONGO database
			# did something actually save to S3
			if k and k.size > 0:

				submitted_image = models.Image()
				submitted_image.title = request.form.get('title')
				submitted_image.description = request.form.get('description')
				submitted_image.postedby = request.form.get('postedby')
				submitted_image.filename = filename # same filename of s3 bucket file
				submitted_image.save()


			return redirect('/')

		else:
			return "uhoh there was an error " + uploaded_file.filename



	else:
		# get existing images
		images = models.Image.objects.order_by('-timestamp')

		# render the template
		templateData = {
			'images' : images,
			'form' : photo_upload_form
		}

		return render_template("upload.html", **templateData)



def datetimeformat(value, format='%H:%M / %d-%m-%Y'):
    return value.strftime(format)


@app.errorhandler(404)
def page_not_found(error):
		# prepare login form
	loginForm = models.LoginForm(request.form)

	templateData = {
		'form' :loginForm,
	}
	return render_template('page_not_found.html', **templateData), 404

if __name__ == '__main__':
    # Bind to PORT if defined, otherwise default to 5000.
    port = int(os.environ.get('PORT', 5000))
    # app.run(host='0.0.0.0', port=port)
app.run(host='127.0.0.1', port=port)