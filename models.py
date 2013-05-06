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

	name = mongoengine.StringField( max_length=30, required=False, verbose_name="Name")
	address = mongoengine.StringField( max_length=30, required=False, verbose_name="Enter Your Address")
	address2 = mongoengine.StringField( max_length=30, required=False, verbose_name="Address 2")	
	zipcode = mongoengine.StringField( max_length=30, required=False, verbose_name="Zipcode")
	state = mongoengine.StringField( max_length=30, required=False, verbose_name="State")
	city = mongoengine.StringField( max_length=30, required=False, verbose_name="city")
	# state = mongoengine.ListField(required=False, verbose_name="State", choices=[('AL' , 'Alabama'), ('AK' , 'Alaska') ,('AZ' , 'Arizona'), ('AR' , 'Arkansas') ,('CA' , 'California'), ('CO' , 'Colorado') ,('CT' , 'Connecticut'), ('DE' , 'Delaware') ,('FL' , 'Florida'), ('GA' , 'Georgia') ,('HI' , 'Hawaii'), ('ID' , 'Idaho') ,('IL' , 'Illinois'), ('IN' , 'Indiana') ,('IA' , 'Iowa'), ('KS' , 'Kansas') ,('KY' , 'Kentucky'), ('LA' , 'Louisiana') ,('ME' , 'Maine'), ('MD' , 'Maryland') ,('MA' , 'Massachusetts'), ('MI' , 'Michigan') ,('MN' , 'Minnesota'), ('MS' , 'Mississippi') ,('MO' , 'Missouri'), ('MT' , 'Montana') ,('NE' , 'Nebraska'), ('NV' , 'Nevada') ,('NH' , 'New Hampshire'), ('NJ' , 'New Jersey') ,('NM' , 'New Mexico'), ('NY' , 'New York') ,('NC' , 'North Carolina'), ('ND' , 'North Dakota') ,('OH' , 'Ohio'), ('OK' , 'Oklahoma') ,('OR' , 'Oregon'), ('PA' , 'Pennsylvania') ,('RI' , 'Rhode Island'), ('SC' , 'South Carolina') ,('SD' , 'South Dakota'), ('TN' , 'Tennessee') ,('TX' , 'Texas'), ('UT' , 'Utah') ,('VT' , 'Vermont'), ('WA' , 'Washington') ,('WV' , 'West Virginia'), ('WI' , 'Wisconsin') ,('WY' , 'Wyoming')])

	active = mongoengine.BooleanField(default=True)
	isAdmin = mongoengine.BooleanField(default=False)
	isResearcher = mongoengine.BooleanField(default=False)
	donated = mongoengine.BooleanField(default=False)
	uuid = mongoengine.IntField(u'UUID', verbose_name="UUID")
	
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

	
user_form = model_form(User, exclude=['password', 'name','address','address2','zipcode','state'])
signup_form = model_form(User, exclude=['name','address','address2','zipcode','state'])
donate_form = model_form(User, exclude=['username','password', 'email'])
uuid_form = model_form(User, exclude=['password','name','email','address','address2','zipcode','state'] )


class Project(mongoengine.Document):
	projectName = mongoengine.StringField(max_length=30, required=False, verbose_name="Project Name")
	location = mongoengine.StringField(max_length=30, required=False, verbose_name="Project Location")
	researcher = mongoengine.StringField(max_length=30, required=False, verbose_name="Researcher Name")
	# user =	mongoengine.ReferenceField('User', dbref=True)
	user =	mongoengine.ListField(mongoengine.ReferenceField('User', dbref=True)) 
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())

project_form = model_form(Project)	
add_user_to_project_form= model_form(Project)	

class Image(mongoengine.Document):

	timeTaken = mongoengine.StringField(verbose_name="Time Taken")
	timeTakenHuman = mongoengine.StringField(verbose_name="Time Taken Human")
	UUID = mongoengine.StringField(verbose_name="Device ID - UUID")
	filename = mongoengine.StringField()
	latitude = mongoengine.FloatField()
	longitude = mongoengine.FloatField()
	batterylife = mongoengine.IntField()
	location = mongoengine.StringField()
	# project = mongoengine.ReferenceField('Project', dbref=True) 
	projectName = mongoengine.StringField()

	# Comments is a list of Document type 'Comments' defined above
	# comments = mongoengine.ListField( mongoengine.EmbeddedDocumentField(Comment) )

	# Timestamp will record the date and time idea was created.
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())


photo_form = model_form(Image)

#Photo Upload Form Created from Photo form
class photo_upload_form(photo_form):
	fileupload = FileField('Upload an image file')



#Project add Form Created from Project form
class addprojectForm(project_form):
	projectName = TextField(u'Project Name')
	location = TextField(u'Location Name')
	researcher = TextField(u'Researcher Name')
	user =	TextField(u'User')
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())
	
class addusertoprojectForm(project_form):
	projectName = SelectField(u'Project Name')
	user =	SelectField(u'User')
	timestamp = mongoengine.DateTimeField(default=datetime.datetime.now())
	
# Signup Form created from user_form
class SignupForm(signup_form):
	password = PasswordField('Password', validators=[validators.Required(), validators.EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')

# Login form will provide a Password field (WTForm form field)
class LoginForm(user_form):
	password = PasswordField('Password',validators=[validators.Required()])

class DonateForm(user_form):
    address  = TextField(u'Address',validators=[validators.Required()])
    address2  = TextField(u'Address 2')
    city  = TextField(u'City',validators=[validators.Required()])
    # state  = TextField(u'State',validators=[validators.Required()])
    state  = SelectField(u'State', choices=[('-' , '-'),('AL' , 'Alabama'), ('AK' , 'Alaska') ,('AZ' , 'Arizona'), ('AR' , 'Arkansas') ,('CA' , 'California'), ('CO' , 'Colorado') ,('CT' , 'Connecticut'), ('DE' , 'Delaware') ,('FL' , 'Florida'), ('GA' , 'Georgia') ,('HI' , 'Hawaii'), ('ID' , 'Idaho') ,('IL' , 'Illinois'), ('IN' , 'Indiana') ,('IA' , 'Iowa'), ('KS' , 'Kansas') ,('KY' , 'Kentucky'), ('LA' , 'Louisiana') ,('ME' , 'Maine'), ('MD' , 'Maryland') ,('MA' , 'Massachusetts'), ('MI' , 'Michigan') ,('MN' , 'Minnesota'), ('MS' , 'Mississippi') ,('MO' , 'Missouri'), ('MT' , 'Montana') ,('NE' , 'Nebraska'), ('NV' , 'Nevada') ,('NH' , 'New Hampshire'), ('NJ' , 'New Jersey') ,('NM' , 'New Mexico'), ('NY' , 'New York') ,('NC' , 'North Carolina'), ('ND' , 'North Dakota') ,('OH' , 'Ohio'), ('OK' , 'Oklahoma') ,('OR' , 'Oregon'), ('PA' , 'Pennsylvania') ,('RI' , 'Rhode Island'), ('SC' , 'South Carolina') ,('SD' , 'South Dakota'), ('TN' , 'Tennessee') ,('TX' , 'Texas'), ('UT' , 'Utah') ,('VT' , 'Vermont'), ('WA' , 'Washington') ,('WV' , 'West Virginia'), ('WI' , 'Wisconsin') ,('WY' , 'Wyoming')],validators=[validators.Required()])
    zipcode  = IntegerField(u'Zipcode',validators=[validators.Required()])

    android  = BooleanField(u'Is your phone an Android Phone?',validators=[validators.Required()])
    condition  = BooleanField(u'Does your phones camera and display work?',validators=[validators.Required()])
    power  = BooleanField(u'Does your phone still hold a charge and power on?',validators=[validators.Required()])
    shipping = RadioField(u'Shipping Options', choices=[('senditmyself','Send it Myself<br><br><div class="span5 formDetails"><small>With this option you use your own packing materials and pay for you own shipping, but you save The Second Nature Project significant shipping costs.</small></div><br><br><br>'),('prepaidshipping', 'Prepaid Shipping Label<br><br><div class="span5 formDetails"><small>With this option you use your own packing materials, but The Second Nature Project will cover the shipping costs.</small></div><br><br>'),('sendmeakit','Send me a shipping kit<br><br><div class="span5 formDetails"><small>With this option The Second Nature Project send you a prepaid package to ship your phone in.</small></div><br><br>')], coerce=unicode)




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
