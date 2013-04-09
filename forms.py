from flaskext.wtf import Form, TextField, Required, PasswordField, validators, SelectField, EqualTo, RadioField, BooleanField
from flaskext.wtf.html5 import EmailField
from flask import Flask, session

class RegisterForm(Form):
	email = EmailField('Email Address', validators=[], description="Enter your email address.")
	password = PasswordField('Password', validators=[Required(), EqualTo('confirm', message='Passwords must match')])
	confirm = PasswordField('Repeat Password')

# class DonateForm(Form):
# 	Android = BooleanField('Is your smartphone and Android Phone?', validators=[Required()])
# 	ScreenCamera = BooleanField('Do your smartphone\'s camera and screen work?', validators=[Required()])
# 	Power = BooleanField('Does your smartphone still power on and hold a charge?', validators=[Required()])

# 	Name = TextField('Name', validators=[Required()], description="Please Name.")
# 	Address = TextField('Address', validators=[Required()], description="Please Enter your mailing address.")
# 	Address2 = TextField('Address2', validators=[], description="Please Enter your mailing address.")
# 	City = TextField('City', validators=[], description="Please Enter your city.")
# 	State = SelectField(u'State', choices=[('AL' , 'Alabama'), ('AK' , 'Alaska') ,('AZ' , 'Arizona'), ('AR' , 'Arkansas') ,('CA' , 'California'), ('CO' , 'Colorado') ,('CT' , 'Connecticut'), ('DE' , 'Delaware') ,('FL' , 'Florida'), ('GA' , 'Georgia') ,('HI' , 'Hawaii'), ('ID' , 'Idaho') ,('IL' , 'Illinois'), ('IN' , 'Indiana') ,('IA' , 'Iowa'), ('KS' , 'Kansas') ,('KY' , 'Kentucky'), ('LA' , 'Louisiana') ,('ME' , 'Maine'), ('MD' , 'Maryland') ,('MA' , 'Massachusetts'), ('MI' , 'Michigan') ,('MN' , 'Minnesota'), ('MS' , 'Mississippi') ,('MO' , 'Missouri'), ('MT' , 'Montana') ,('NE' , 'Nebraska'), ('NV' , 'Nevada') ,('NH' , 'New Hampshire'), ('NJ' , 'New Jersey') ,('NM' , 'New Mexico'), ('NY' , 'New York') ,('NC' , 'North Carolina'), ('ND' , 'North Dakota') ,('OH' , 'Ohio'), ('OK' , 'Oklahoma') ,('OR' , 'Oregon'), ('PA' , 'Pennsylvania') ,('RI' , 'Rhode Island'), ('SC' , 'South Carolina') ,('SD' , 'South Dakota'), ('TN' , 'Tennessee') ,('TX' , 'Texas'), ('UT' , 'Utah') ,('VT' , 'Vermont'), ('WA' , 'Washington') ,('WV' , 'West Virginia'), ('WI' , 'Wisconsin') ,('WY' , 'Wyoming')])
# 	Zipcode = TextField('Zipcode', validators=[], description="Please Enter your zipcode.")