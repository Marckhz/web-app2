import functools

from flask import ( Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash
from flaskr.db import get_db


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
	if request.method =='POST':

		username = request.form['username']
		email = request.form['email']
		password = request.form['password']

		db = get_db()
		error = None

		if not username:
			error = 'Username is required'
		elif not email:
			error = 'Email is required'
		elif not password:
			error = 'Password is required'
		elif db.execute(
			'SELECT id FROM user WHERE username = ?', (username,)
			).fetchone() is not None:
			error = 'User {} is already registered'.format(username)
		


		if error is None:
			db.execute(
				'INSERT INTO user (username, email, password) VALUES (?,?,?)',
				(username, email, generate_password_hash(password))
				)
			db.commit()
			return redirect(url_for('auth.login'))

		flash(error)

	return render_template('auth/register.html')



@bp.route('/login', methods=('GET', 'POST'))
def login():

	if request.method == 'POST':
		username = request.form['username']
		password = request.form['password']

		db = get_db()
		error = None
		user = db.execute(
			'SELECT  * FROM user WHERE username= ?', (username,)
			).fetchone()
		if user is None:
			error = 'Incorrect username'
		elif not check_password_hash(user['password'], password):
			error = 'Incorrect password'

		if error is None:
			session.clear()
			session['user_id'] = user['id']
			return redirect(url_for('index'))
		flash(error)



	return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():

	user_id = session.get('user_id')

	if user_id	is None:
		g.user = None

	else:
		g.user = get_db().execute(
			'SELECT * FROM user WHERE id = ? ', (user_id,)
			).fetchone()


bp.route('/logout')
def logout():
	session.clear()
	return redirect(url_for('index'))


def login_required(view):
	@functools.wraps(view)
	def wrapped_view(**kwargs):
		if g.user is None:
			return redirect(url_for('auth.login'))
		
		return view(**kwargs)
	return wrapped_view

@bp.route('/buy_woman')
def buy_woman():

	return render_template('auth/buy_woman.html')

@bp.route('/the_skater')
def the_skater():

	return render_template('auth/the_skater.html')

@bp.route('/the_bird')
def the_bird():

	return render_template('auth/the_bird.html')

@bp.route('/the_hand')
def the_hand():

	return render_template('auth/the_hand.html')

@bp.route('/the_pencil')
def the_pencil():

	return render_template('auth/the_pencil.html')

@bp.route('/the_air')
def the_air():

	return render_template('auth/the_air.html')	

@bp.route('/the_comic')
def the_comic():

	return render_template('auth/the_comic.html')

@bp.route('/more_pencils')
def more_pencils():

	return render_template('auth/more_pencils.html')