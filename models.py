# -*- coding: utf-8 -*-
from flask.ext.mongoengine.wtf import model_form
from wtforms.fields import * # for our custom signup form
from flask.ext.mongoengine.wtf.orm import validators
from flask.ext.mongoengine import *
import datetime

    
class User(mongoengine.Document):
	username = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Pick a Username")
	email = mongoengine.EmailField(unique=True, required=True, verbose_name="Email Address")
	password = mongoengine.StringField(default=True,required=True)

	# name = mongoengine.StringField(unique=True, max_length=30, required=False, verbose_name="Name")
	# address = mongoengine.StringField(unique=True, max_length=30, required=False, verbose_name="Enter Your Address")
	# address2 = mongoengine.StringField(unique=True, max_length=30, required=False, verbose_name="Address 2")	
	# zipcode = mongoengine.StringField(unique=True, max_length=30, required=False, verbose_name="Zipcode")
	# state = mongoengine.ListField(unique=True, required=False, verbose_name="State", choices=[('AL' , 'Alabama'), ('AK' , 'Alaska') ,('AZ' , 'Arizona'), ('AR' , 'Arkansas') ,('CA' , 'California'), ('CO' , 'Colorado') ,('CT' , 'Connecticut'), ('DE' , 'Delaware') ,('FL' , 'Florida'), ('GA' , 'Georgia') ,('HI' , 'Hawaii'), ('ID' , 'Idaho') ,('IL' , 'Illinois'), ('IN' , 'Indiana') ,('IA' , 'Iowa'), ('KS' , 'Kansas') ,('KY' , 'Kentucky'), ('LA' , 'Louisiana') ,('ME' , 'Maine'), ('MD' , 'Maryland') ,('MA' , 'Massachusetts'), ('MI' , 'Michigan') ,('MN' , 'Minnesota'), ('MS' , 'Mississippi') ,('MO' , 'Missouri'), ('MT' , 'Montana') ,('NE' , 'Nebraska'), ('NV' , 'Nevada') ,('NH' , 'New Hampshire'), ('NJ' , 'New Jersey') ,('NM' , 'New Mexico'), ('NY' , 'New York') ,('NC' , 'North Carolina'), ('ND' , 'North Dakota') ,('OH' , 'Ohio'), ('OK' , 'Oklahoma') ,('OR' , 'Oregon'), ('PA' , 'Pennsylvania') ,('RI' , 'Rhode Island'), ('SC' , 'South Carolina') ,('SD' , 'South Dakota'), ('TN' , 'Tennessee') ,('TX' , 'Texas'), ('UT' , 'Utah') ,('VT' , 'Vermont'), ('WA' , 'Washington') ,('WV' , 'West Virginia'), ('WI' , 'Wisconsin') ,('WY' , 'Wyoming')])

	active = mongoengine.BooleanField(default=True)
	isAdmin = mongoengine.BooleanField(default=False)
	donated = mongoengine.BooleanField(default=False)
	UUID = mongoengine.UUIDField(binary=False	) #Should this be multiple and how to handle arrays?
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

user_form = model_form(User, exclude=['password'])
donate_form = model_form(User, exclude=['username','email','password'])

# class Address(mongoengine.Document):
# 	address = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Please Enter Your Address")
# 	address2 = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Address 2")
# 	zipcode = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Zipcode")


# 	active = mongoengine.BooleanField(default=True)
# 	isAdmin = mongoengine.BooleanField(default=False)
# 	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

# class Project(mongoengine.Document):
# 	name = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Project Name")
# 	location = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Project Location")
# 	researcher = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Researcher Name")
# 	UUIDS = mongoengine.UUIDField() #Should this be multiple and how to handle arrays?
# 	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

# class Researcher(mongoengine.Document):
# 	username = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Pick a Username")
# 	email = mongoengine.EmailField(unique=True, required=True, verbose_name="Email Address")
# 	password = mongoengine.StringField(default=True,required=True)

# 	name = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Pick a Username")
# 	address = mongoengine.StringField(unique=True, max_length=30, required=False, verbose_name="Please Enter Your Address")
# 	address2 = mongoengine.StringField(unique=True, max_length=30, required=False, verbose_name="Address 2")	
# 	zipcode = mongoengine.StringField(unique=True, max_length=30, required=True, verbose_name="Zipcode")
# 	state = mongoengine.ListField(unique=True, required=True, verbose_name="State")

# 	active = mongoengine.BooleanField(default=True)
# 	isAdmin = mongoengine.BooleanField(default=False)
# 	donated = mongoengine.BooleanField(default=False)
# 	UUID = mongoengine.UUIDField() #Should this be multiple and how to handle arrays?
# 	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())


# Signup Form created from user_form
class SignupForm(user_form):
	password = PasswordField('Password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')

# Login form will provide a Password field (WTForm form field)
class LoginForm(user_form):
	password = PasswordField('Password',validators=[validators.Required()])

# Donate form will provide a Password field (WTForm form field)
# class DonateForm(user_form):
# 	Android = BooleanField('Is your smartphone and Android Phone?', validators=[Required()])
# 	ScreenCamera = BooleanField('Do your smartphone\'s camera and screen work?', validators=[Required()])
# 	Power = BooleanField('Does your smartphone still power on and hold a charge?', validators=[Required()])

# 	Name = TextField('Name', validators=[Required()], description="Please Name.")
# 	Address = TextField('Address', validators=[Required()], description="Please Enter your mailing address.")
# 	Address2 = TextField('Address2', validators=[], description="Please Enter your mailing address.")
# 	City = TextField('City', validators=[], description="Please Enter your city.")
# 	State = SelectField(u'State', choices=[('AL' , 'Alabama'), ('AK' , 'Alaska') ,('AZ' , 'Arizona'), ('AR' , 'Arkansas') ,('CA' , 'California'), ('CO' , 'Colorado') ,('CT' , 'Connecticut'), ('DE' , 'Delaware') ,('FL' , 'Florida'), ('GA' , 'Georgia') ,('HI' , 'Hawaii'), ('ID' , 'Idaho') ,('IL' , 'Illinois'), ('IN' , 'Indiana') ,('IA' , 'Iowa'), ('KS' , 'Kansas') ,('KY' , 'Kentucky'), ('LA' , 'Louisiana') ,('ME' , 'Maine'), ('MD' , 'Maryland') ,('MA' , 'Massachusetts'), ('MI' , 'Michigan') ,('MN' , 'Minnesota'), ('MS' , 'Mississippi') ,('MO' , 'Missouri'), ('MT' , 'Montana') ,('NE' , 'Nebraska'), ('NV' , 'Nevada') ,('NH' , 'New Hampshire'), ('NJ' , 'New Jersey') ,('NM' , 'New Mexico'), ('NY' , 'New York') ,('NC' , 'North Carolina'), ('ND' , 'North Dakota') ,('OH' , 'Ohio'), ('OK' , 'Oklahoma') ,('OR' , 'Oregon'), ('PA' , 'Pennsylvania') ,('RI' , 'Rhode Island'), ('SC' , 'South Carolina') ,('SD' , 'South Dakota'), ('TN' , 'Tennessee') ,('TX' , 'Texas'), ('UT' , 'Utah') ,('VT' , 'Vermont'), ('WA' , 'Washington') ,('WV' , 'West Virginia'), ('WI' , 'Wisconsin') ,('WY' , 'Wyoming')])
# 	Zipcode = TextField('Zipcode', validators=[], description="Please Enter your zipcode.")
	

#################  end of user models/forms ##########################


class Content(mongoengine.Document):
    user = mongoengine.ReferenceField('User', dbref=True) # ^^^ points to User model ^^^
    title = mongoengine.StringField(max_length="100",required=True)
    content = mongoengine.StringField(required=True)
    timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

    @mongoengine.queryset_manager
    def objects(doc_cls, queryset):
    	return queryset.order_by('-timestamp')

# content form
content_form = model_form(Content)
