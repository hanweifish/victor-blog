
import os
import re
import hmac
import hashlib
import random
from string import letters

import jinja2
import webapp2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2. Environment(loader = jinja2. FileSystemLoader(template_dir),
	autoescape = True)

secret = 'victor'

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env. get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
    

  	def set_secure_cookie(self, name, val):
  		cookie_val = make_secure_val(val)
  		self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

  	def read_secure_cookie(self, name): 
  		cookie_val = self.request.cookies.get(name)
   		return cookie_val and check_secure_val(cookie_val)

  	def login(self, user):
  		self.set_secure_cookie('user_id', str(user.key().id()))

  	def logout(self):
  		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

  	def initialize(self, *a, **kw):
  		webapp2.RequestHandler.initialize(self, *a, **kw)
  		uid = self.read_secure_cookie('user_id')
  		self.user = uid and User.by_id(int(uid))


			
####User Login

def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
	return db.Key.from_path('users', group)


class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid, parent = users_key())

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = users_key(),
					name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		u = User.by_name(name)
		if u and valid_pw(name, pw, u.pw_hash):
			return u


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return password and PASS_RE.match(password)

#Email is the option case
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
	return not email or EMAIL_RE.match(email)


class Signup(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		have_error = False
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username, email = self.email)

		if not valid_username(self.username):
			params['error_username'] = "That's not a valid username."
			have_error = True

		if not valid_password(self.password):
			params['error_password'] = "That wasn't a valid password."
			have_error = True
		elif self.password != self.verify:
			params['error_verify'] = "Your passwords didn't match."
			have_error = True

		if not valid_email(self.email):	
			params['error_email'] = "That's not a valid email." 
			have_error = True

		if have_error:
			self.render('signup.html', **params)
		else:
			self.done()

	def done(self, *a, **kw):
		raise NotImplementedError


class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/private')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)


class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')		


###Private Page
def Page_key(name = 'default'):
    return db.Key.from_path('Pages', name)

class Blog(db.Model):
	user_id = db.IntegerProperty(required = True)
	username = db.StringProperty(required = True)
	title = db.StringProperty(required = True)
	content = db. TextProperty(required = True)
	created_time = db. DateTimeProperty(auto_now_add = True)


class EditPage(Handler):
    def get(self):
        if self.user:
            self.render("edit.html", user = self.user)
        else:
            self.redirect("/login")

    def post(self,):
        if not self.user:
            self.redirect('/login')

        title = self.request.get('title')
        content = self.request.get('content')
        user_id = self.user.key().id()
        username = self.user.name


        if content and title and user_id and username:
            p = Blog(parent = Page_key(), user_id = user_id, content = content, title = title, username = username)
            p.put()
            self.redirect("/private")
        else:
            error = "Please fill the title and content, please!"
            self.render("edit.html", content=content, title = title, error=error)



class PrivatePage(Handler):
    def render_post(self):
    	if not self.user:
            self.redirect('/login')
        else:
	    	user_id = self.user.key().id()
    		blog_list = db.GqlQuery("Select * from Blog where user_id = :user_id order by created_time Desc", user_id = user_id)
    		self.render("private.html", blog_list = blog_list, user = self.user)


    def get(self):
        self.render_post()


class MainPage(Handler):
	def write_page(self, user = None):
		blog_list = db.GqlQuery("Select * from Blog order by created_time Desc")
		if self.user:
			user = self.user
		self.render("mainpage.html", blog_list = blog_list, user = user)
		

	def get(self):
		self.write_page()

app = webapp2.WSGIApplication([('/', MainPage),
								('/signup', Register),
								('/login', Login),
								('/logout', Logout),
								('/edit', EditPage),
								('/private', PrivatePage)],
								debug=True)