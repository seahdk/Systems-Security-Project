import datetime
import random
import smtplib
from tkinter import *
from tkinter import messagebox

import MySQLdb.cursors
import flask
import flask_login
import requests
from captcha.image import ImageCaptcha
from cryptography.fernet import Fernet
from flask import Blueprint
from flask import Flask, request
from flask import render_template, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mysqldb import MySQL
from itsdangerous import URLSafeSerializer, SignatureExpired
from twilio.rest import Client

import twiliokey

app = Flask(__name__)
user = None
global OTPCheck
msg = ""

bcrypt = Bcrypt()

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'Dingkai'
s=URLSafeSerializer("Jon")


#all password are Pass123#

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 't0227016h'  #Change This
app.config['MYSQL_DB'] = 'pythonlogin'

# Intialize MySQL
mysql = MySQL(app)

# http://localhost:5000/MyWebApp/ - this will be the login page, we need to use both GET and POST


# flask-limiter initiation part
login = Blueprint("login", __name__, url_prefix = "/")
register = Blueprint("register", __name__, url_prefix = "/register")
home = Blueprint("home", __name__, url_prefix = "/home")
profile = Blueprint('profile', __name__, url_prefix = "/profile")
logout = Blueprint("logout", __name__, url_prefix = "/logout")
notification = Blueprint("notification", __name__, url_prefix = "/notifications")
activity = Blueprint("activity", __name__, url_prefix = "/activity")



list = []


@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(seconds=5)  # This works which is feature 1, change the seconds
    flask.session.modified = True
    flask.g.user = flask_login.current_user


@app.route('/')
def abc():
    return redirect(url_for('login'))

@app.route("/MyWebApp/", methods=["GET", "POST"])
def login():
    global OTPCheck
    OTPCheck = False
    session["ip_address"] = ""
    session["loggedin"] = False
    session["user_id"] = ""
    session["username"] = ""
    msg = ""

    # Output message if something goes wrong...
    msg = ""
    # Check if "username" and "password" POST requests exist (user submitted form)
    if request.method == "POST" and "username" in request.form and "password" in request.form:
        try:
            # Create variables for easy access
            username = request.form["username"]
            password = request.form["password"]
            malicious_input = is_malicious_input([username, password])
            current_session_data = get_current_session_data()
            malicious_input = is_malicious_input([username, password])
            if malicious_input:
                log_malicious_activity(
                False,
                "Malicious user input submitted",
                str(malicious_input)
                + "{'username':'"
                + username
                + "','password':'"
                + password
                + "'}",
                current_session_data,
                )

            user = get_user(username)
            user_hashpwd = user.get('password')
        except:
            current_session_data = get_current_session_data()
            msg = "Invalid login credentials"
            log_malicious_activity(
                False,
                "Login attempt using an inexisting account username",
                "Username ='" + username + "' and Password = '" + password + "'",
                current_session_data,
            )
            return render_template("index.html", msg=msg)
        current_session_data = get_current_session_data()
        malicious_input = is_malicious_input([username, password])
        if malicious_input:
            log_malicious_activity(
                False,
                "Malicious user input submitted",
                str(malicious_input)
                + "{'username':'"
                + username
                + "','password':'"
                + password
                + "'}",
                current_session_data,
            )

        user = get_user(username)
        if user:
            print(user["is_blocked"])
            if user["is_blocked"] == "YES":
                msg = "Your account is blocked. Please contact the admin"
                # Show the login form with message (if any)
                log_malicious_activity(
                    False,
                    "A blocked user account attempting to log in",
                    "Username ='" + username + "' and Password = '" + password + "'",
                    current_session_data,
                )
                return render_template("index.html", msg=msg)

            user_hashpwd = user["password"]

            if bcrypt.check_password_hash(user_hashpwd, password):
                # Create session data, we can access this data in other routes
                session["user_id"] = user.get('id')
                session["username"] = user.get('username')
                # Get details of the user/device attempting to access the login page
            else:
                # Account doesn’t exist or username/password incorrect
                msg = "Invalid login credentials"
                # Record the invalid login attempt
                log_malicious_activity(
                    False,
                    "Login attempt using invalid credentials",
                    "Username ='" + username + "' and Password = '" + password + "'",
                    current_session_data,
                )

                return redirect(url_for("login"))
            if bcrypt.check_password_hash(user_hashpwd, password):
                # Create session data, we can access this data in other routes
                session["loggedin"] = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]

                if current_session_data:
                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute(
                    "INSERT INTO logs VALUES (NULL, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ON DUPLICATE KEY UPDATE city=%s, region=%s, country_name=%s, continent_code=%s, latitude=%s, longitude=%s, network_provider=%s, is_active_session=%s",
                            (
                                user["id"],
                                current_session_data["ip"],
                                current_session_data["city"],
                                current_session_data["region"],
                                current_session_data["country_name"],
                                current_session_data["continent_code"],
                                current_session_data["latitude"],
                                current_session_data["longitude"],
                                current_session_data["org"],
                                "Active",
                                current_session_data["city"],
                                current_session_data["region"],
                                current_session_data["country_name"],
                                current_session_data["continent_code"],
                                current_session_data["latitude"],
                                current_session_data["longitude"],
                                current_session_data["org"],
                                "Active",
                            ),
                    )
                    mysql.connection.commit()
                    session["ip_address"] = current_session_data["ip"]
                    # Check if the user logs in from a foreign country
                    if user["country"] == current_session_data["country_name"]:
                        if user.get('role') == "user" and bcrypt.check_password_hash( user_hashpwd, password):
                            window = login_otp()
                            window.button()
                            window.mainloop()
                            try:
                                if OTPCheck == True:
                                    msg = 'You have successfully registered!'

                                elif OTPCheck == False:
                                    msg = 'Failed OTP'
                                    return render_template("index.html", msg=msg)
                            except:
                                msg = 'Name has already been taken or OTP was closed'
                                return render_template('register.html', msg=msg)
                            session['role'] = "user"
                            session['loggedin']= True
                            session['id'] = user.get("id")
                            session['username'] = user.get("username")
                            encrypted_email = user.get('email').encode()
                            file = open('symmetric.key', 'rb')
                            key = file.read()
                            file.close()
                            f = Fernet(key)
                            decrypted_email = f.decrypt(encrypted_email)
                            user_id = session['user_id']

                            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                            cursor.execute("SELECT * FROM logs WHERE user_id = %s", (user_id,))
                            logs = cursor.fetchall()
                            x = 0
                            for i in logs:
                                if i.get('is_active_session') == "Active":
                                    x += 1
                                else:
                                    x = x
                            if x >= 2:
                                return redirect(url_for("force"))
                            else:
                                 return redirect(url_for("home"))
                        elif user.get('role') == "admin":
                            session["role"] = "admin"
                            return redirect(url_for("admin"))
                        else:
                            return redirect(url_for("login"))

                    elif not user["country"] == current_session_data["country_name"]:
                        log_malicious_activity(
                            True,
                            "Login from an unfamiliar location",
                            None,
                            current_session_data,
                        )

@app.route("/MyWebApp/activity")
def activity():
    if "loggedin" in session:

        current_session_ip = get_current_session_data()["ip"]

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM logs WHERE user_id = %s ORDER BY `is_active_session` DESC, `activity_time` DESC",
            (session["user_id"],),
        )
        # Fetch one record and return result
        sessions = cursor.fetchall()

        return render_template(
            "activity.html",
            account=user,
            sessions=sessions,
            current_session_ip=current_session_ip,
        )
    return redirect(url_for("login"))

# http://localhost:5000/MyWebApp/logout - this will be the logout page
@app.route("/MyWebApp/logout")
def logout():
    # Deactivate session from database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "UPDATE `logs` SET `is_active_session` = 'Inactive' WHERE `logs`.`user_id` = %s and `ip_address`=%s",
        (
            session["user_id"],
            session["ip_address"],
        )
    )
    mysql.connection.commit()
    # Remove session data, this will log the user out
    session['loggedin'] = False
    session.pop("session_ip", None)
    session.pop("session_id", None)
    session.pop("username", None)
    session.pop("role", None)
    session.pop("user_id", None)
    session.pop("ip_address", None)
    session.pop("id", None)
    # Redirect to login page
    return redirect(url_for("login"))

@app.route("/MyWebApp/ForceLogout")
def force():
    # Deactivate session from database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "UPDATE `logs` SET `is_active_session` = 'Inactive' WHERE `logs`.`user_id` = %s",
        (
            session["user_id"],
        )
    )
    mysql.connection.commit()
    # Remove session data, this will log the user out
    session['loggedin'] = False
    session.pop("session_ip", None)
    session.pop("session_id", None)
    session.pop("username", None)
    session.pop("role", None)
    session.pop("user_id", None)
    session.pop("ip_address", None)
    session.pop("id", None)
    # Redirect to login page
    return render_template('index.html', msg = "Another Person Was Logged In, Was It You?")

@app.route("/MyWebApp/forgotpsw")
def forgotpsw():
    window = passwordchange()
    window.button2()
    window.mainloop()
    return redirect(url_for("login"))


# http://localhost:5000/MyWebApp/register - this will be the registration page, we need to use both GET and POST requests
@app.route('/MyWebApp/register', methods=['GET', 'POST'])
def register():
    global OTPCheck
    num = get_captcha(list)
    bcrypt = Bcrypt()
    # Output message if something goes wrong...
    msg = ''
    # Check if "username", "password" and "email" POST requests exist (user submitted form)
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form \
    and 'email' in request.form and 'phone' in request.form and 'country' in request.form and 'captcha' in request.form:
        # Create variables for easy access
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        email = email.encode()
        role = request.form["role"]
        country = request.form["country"]
        CAPTCHA = request.form['captcha']
        if int(CAPTCHA) == int(list[0]):
            hashpwd = bcrypt.generate_password_hash(password)
            if password_check(password) == False:
                return render_template('register.html', msg = "Password Requirements: 8 length, 1 digit, 1 symbol,1 uppercase letter, 1 lowercase Not Met")
            try:
                with open("symmetric.key", "rb") as fo:
                    key = fo.read()
                    fo.close()

            except:
                key = Fernet.generate_key()

                with open("symmetric.key", "wb") as fo:
                    fo.write(key)

            f = Fernet(key)

            encrypted_email = f.encrypt(email)

            # Optional challenge : Check for duplicate acct and perform form validation
            # Account doesnt exists and the form data is valid, now insert new account into accounts table

            #This is one dumb feature that took 9hours of research
            #otp = random.randint(1000,9999)
            '''
            client = Client(twiliokey.account_sid, twiliokey.auth_token)
            #change Body to whatever message you want
            messages = client.messages.create(
                          body=('Your OTP is {{otp}}'),
                          from_=twiliokey.twilio_number,
                          to=phone) #make sure phone number is verified in twilio at https://console.twilio.com/us1/develop/phone-numbers/manage/verified
            '''
            window = otp_verifier()
            window.button()
            window.mainloop()
            if OTPCheck == True:
                        print("true")
                        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s, %s, %s)', (username, hashpwd, encrypted_email, role, country, "No", phone))
                        mysql.connection.commit()

                        msg = 'You have successfully registered!'

            elif OTPCheck == False:
                        msg = 'Failed OTP'
                        return render_template("index.html", msg=msg)
            else:
                msg = 'Name has already been taken or OTP was closed'
                return render_template('register.html', msg=msg)
        elif int(CAPTCHA) != int(list[0]):
             msg = 'the captcha entered was wrongly'

    elif request.method == 'POST':
        # Form is empty... (no POST data)
        msg = 'Please fill out the form!'
        # Show registration form with message (if any)

    return render_template('register.html', msg=msg, num=num)

# http://localhost:5000/MyWebApp/home - this will be the home page, only accessible for loggedin users
@app.route('/MyWebApp/home')
def home():
    msg = ''
    # Check if user is loggedin
    if session['loggedin'] == True:
        user = get_user(session['username'])
        encrypted_email = user.get('email').encode()
        file = open('symmetric.key', 'rb')
        key = file.read()
        file.close()
        f = Fernet(key)
        decrypted_email = f.decrypt(encrypted_email)
        x = str(decrypted_email).strip("b'' ")
        Z = session['username']
        msg = "Inactivity will result in session termination."
        print(msg)
        return render_template('home.html', username=Z, decrypted_email=x, msg = msg)
    elif session['loggedin'] == False:
        return redirect(url_for('login'))
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/MyWebApp/profile', methods=['GET', 'POST'])
def profile():
    # Check if user is loggedin
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        user = get_user(session['username'])
        enc_email = user.get('email').encode()

        file = open('symmetric.key', 'rb')
        key = file.read()
        file.close()

        f = Fernet(key)
        dec_email = f.decrypt(enc_email)
        username = session['username']
        mail = str(dec_email).strip("b'' ")

        if request.method == 'POST':
            token = s.dumps(mail, salt='token_cmf')
            link = url_for('update', token=token, _external=True)
            send_cmf(mail, link)
            print('email has been sent, the token is', token)

        # Show the profile page with account info
        return render_template('profile.html', username=username, email=mail)
    # User is not loggedin redirect to login page
    return redirect(url_for('login'))


def send_cmf(email, link):
    msg = "Hi, \nYour confirmation link is: {}".format(link)
    smtplibObj = smtplib.SMTP("smtp.gmail.com", 587)
    smtplibObj.ehlo()
    smtplibObj.starttls()
    smtplibObj.login("ngdingxuanxu@gmail.com", "pxdguyrqxgkznlgx")
    smtplibObj.sendmail("ngdingxuanxu@gmail.com", email, msg)
    smtplibObj.quit()


@app.route('/MyWebApp/update/<token>')
def update(token):
    if 'loggedin' in session:
        try:
            email = s.loads(token, salt='token_cmf', max_age=900)
        except SignatureExpired:
            return '<h1>token has expired</h1>'
        return render_template("update.html", username=session['username'])
    return redirect(url_for('login'))


def get_captcha(list):
    num = random.randint(1000, 9999)
    captcha = ImageCaptcha()
    captcha.write(str(num), f'./static/{num}.png')
    list.append(num)
    if len(list) > 2:
        list.remove(list[0])
    return num



#DK
def get_user(username):
    # Check if account exists using MySQL
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM accounts WHERE username = %s", (username,))
    # Fetch record and return username
    account = cursor.fetchone()
    mysql.connection.commit()
    return account

def get_current_session_data():
    try:
        return requests.get(f"https://ipapi.co/json/").json()
    except:
        return None

class otp_verifier(Tk):
    def __init__(self):
        super().__init__()
        self.geometry("600x550")
        self.resizable(False,False)
        self.n = str(random.randint(1000,9999))

        self.c = Canvas(self, bg = 'white', width = 400, height = 280)
        self.c.place(x=100,y=60)

        self.Login_Title = Label(self,text = "OTP Verification", font= "bold", bg = "white")
        self.Login_Title.place(x=210,y=90)

        self.User_Name=Text(self, borderwidth= 2, wrap='word',width=29,height=2)
        self.User_Name.place(x=190,y=160)

    def checkOTP(self):
        global OTPCheck
        OTPCheck = False
        OTPCheck = None
        self.userInput=str(self.User_Name.get(1.0,"end-1c"))
        if self.userInput == self.n:
            messagebox.showinfo("showinfo","Login Success")
            OTPCheck = True
            return True
        else:
            messagebox.showinfo("showinfo", "wrong OTP")
            OTPCheck = False
            return False

    def button(self):
        self.sendOTP = Button(self,text = "Send OTP", command=self.sendOTP)
        self.sendOTP.place(x= 190, y= 400)

        self.verifybutton = Button(self,text = "Verify", command=self.checkOTP)
        self.verifybutton.place(x= 390, y= 400)

    def sendOTP(self):
        self.n = str(random.randint(1000,9999))
        #self.n = "1234"

        phone = request.form['phone']
        self.client = Client(twiliokey.account_sid, twiliokey.auth_token)
        #change Body to whatever message you want
        self.client.messages.create(
                      body=self.n,
                      from_=twiliokey.twilio_number,
                      to=phone) #make sure phone number is verified in twilio at https://console.twilio.com/us1/develop/phone-numbers/manage/verified

class login_otp(Tk):
    def __init__(self):
        super().__init__()
        self.geometry("600x550")
        self.resizable(False,False)
        self.n = str(random.randint(1000,9999))

        self.c = Canvas(self, bg = 'white', width = 400, height = 280)
        self.c.place(x=100,y=60)

        self.Login_Title = Label(self,text = "OTP Verification", font= "bold", bg = "white")
        self.Login_Title.place(x=210,y=90)

        self.User_Name=Text(self, borderwidth= 2, wrap='word',width=29,height=2)
        self.User_Name.place(x=190,y=160)

    def checkOTP(self):
        global OTPCheck
        OTPCheck = False
        OTPCheck = None
        self.userInput=str(self.User_Name.get(1.0,"end-1c"))
        if self.userInput == self.n:
            messagebox.showinfo("showinfo","Login Success")
            OTPCheck = True
            return True
        else:
            messagebox.showinfo("showinfo", "wrong OTP")
            OTPCheck = False
            return False

    def button(self):
        self.sendOTP = Button(self,text = "Send OTP", command=self.sendOTP)
        self.sendOTP.place(x= 190, y= 400)

        self.verifybutton = Button(self,text = "Verify", command=self.checkOTP)
        self.verifybutton.place(x= 390, y= 400)

    def sendOTP(self):
        self.n = str(random.randint(1000,9999))
        #self.n = "1234"

        username = request.form['username']
        user = get_user(username)
        phone = user.get('phone')
        self.client = Client(twiliokey.account_sid, twiliokey.auth_token)
        #change Body to whatever message you want
        self.client.messages.create(
                      body=self.n,
                      from_=twiliokey.twilio_number,
                      to=phone) #make sure phone number is verified in twilio at https://console.twilio.com/us1/develop/phone-numbers/manage/verified


class passwordchange(Tk):
    def __init__(self):
        super().__init__()
        self.geometry("600x550")
        self.resizable(False,False)

        self.c = Canvas(self, bg = 'white', width = 400, height = 280)
        self.c.place(x=100,y=60)

        self.username = Label(self,text = "Username", font= "bold", bg = "white")
        self.username.place(x=190,y=100)

        self.User_Name=Text(self, borderwidth= 2, wrap='word',width=29,height=2)
        self.User_Name.place(x=190,y=130)

        self.email = Label(self,text = "Email", font= "bold", bg = "white")
        self.email.place(x=190,y=170)

        self.Email=Text(self, borderwidth= 2, wrap='word',width=29,height=2)
        self.Email.place(x=190,y=200)

        self.password = Label(self,text = "New Password", font= "bold", bg = "white")
        self.password.place(x=190,y=250)

        self.newPassword=Text(self, borderwidth= 2, wrap='word',width=29,height=2)
        self.newPassword.place(x=190,y=280)


        # ========= DATABASE CONNECTION FOR FORGOT PASSWORD=====================
    def change_password(self):
        self.userInput=str(self.User_Name.get(1.0,"end-1c"))

        self.userInputEmail=str(self.Email.get(1.0,"end-1c"))

        self.userInputPassword=str(self.newPassword.get(1.0,"end-1c"))

        user = get_user(self.userInput)
        email = user.get('email').encode()
        encrypted_email = email

        with open("symmetric.key", "rb") as fo:
                key = fo.read()
                fo.close()
                f = Fernet(key)
                decrypted_email = f.decrypt(encrypted_email)
                x = str(decrypted_email).strip(",'' b")

        if self.userInput == user.get('username') and self.userInputEmail == x:
        #if self.userInput == user.get('username') and encrypted_email2 == encrypted_email:
            if password_check(self.userInputPassword) == False:
                messagebox.showerror("Password Requirements:", '8 letter length\n' '1 digit\n' "1 symbol\n" "1 uppercase letter\n" "1 lowercase\n")
            else:
                hashpwd = bcrypt.generate_password_hash(self.userInputPassword)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                command ='UPDATE accounts SET password = %s WHERE username = %s AND email = %s'
                Input = hashpwd, self.userInput, user.get('email')
                cursor.execute(command,Input)
                mysql.connection.commit()
                messagebox.showinfo('Congrats', 'Password changed successfully')
        else:
            messagebox.showerror('Error!', "No such account")

    def button2(self):
        self.change = Button(self,text = "Change", command=self.change_password)
        self.change.place(x= 280, y= 400)



@app.route("/MyWebApp/admin")
def admin():
    # Check if user is loggedin
    if "loggedin" in session:
        # User is loggedin show them the home page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM logs INNER JOIN accounts ON accounts.id=logs.user_id"
        )
        # Fetch one record and return result
        logs = cursor.fetchall()
        return render_template("admin.html", username=session["username"], logs=logs)
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))

def password_check(password):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) <= 7

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return password_ok




#changes start here dingkai


@app.route("/MyWebApp/notifications")
def notifications():
    # Check if user is loggedin
    if "loggedin" in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM notifications WHERE username = %s ORDER BY `time` DESC",
            (session["username"],),
        )
        # Fetch one record and return result
        notifications = cursor.fetchall()
        return render_template("notifications.html", notifications=notifications)
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))


@app.route("/MyWebApp/admin_notifications")
def admin_notifications():
    # Check if user is loggedin
    if "loggedin" in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "SELECT * FROM notifications ORDER BY `time` DESC",
        ),
        # Fetch one record and return result
        notifications = cursor.fetchall()
        return render_template("admin_notifications.html", notifications=notifications)
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))

@app.route("/MyWebApp/block_user/<username>")
def block_user(username):
    if "loggedin" in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "UPDATE `notifications` SET `ip_blocked` = '1' WHERE `username` = %s",
            (username,),
        )
        mysql.connection.commit()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "UPDATE `accounts` SET `is_blocked` = 'YES' WHERE `username` = %s",
            (username,),
        )
        mysql.connection.commit()
        return redirect(url_for("admin_notifications"))
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))


@app.route("/MyWebApp/unblock_user/<username>")
def unblock_user(username):
    if "loggedin" in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "UPDATE `notifications` SET `ip_blocked` = 0 WHERE `username` = %s",
            (str(username),),
        )
        mysql.connection.commit()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "UPDATE `accounts` SET `is_blocked` = 'NO' WHERE `username` = %s",
            (str(username),),
        )
        mysql.connection.commit()
        return redirect(url_for("admin_notifications"))
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))


@app.route("/MyWebApp/block_ip/<ip_address>")
def block_ip(ip_address):
    if "loggedin" in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "UPDATE `notifications` SET `ip_blocked` = '1' WHERE `ip_address` = %s",
            (str(ip_address),),
        )
        mysql.connection.commit()
        return redirect(url_for("admin_notifications"))
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))


@app.route("/MyWebApp/ublock_ip/<ip_address>")
def unblock_ip(ip_address):
    if "loggedin" in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            "UPDATE `notifications` SET `ip_blocked` = 0 WHERE `ip_address` = %s",
            (str(ip_address),),
        )
        mysql.connection.commit()
        return redirect(url_for("admin_notifications"))
    # User is not loggedin redirect to login page
    return redirect(url_for("login"))

def is_malicious_input(input):
    for field in input:
        # Malicious input will contain scripts
        if field is not None and ("<script" in field):
            return field
    return False

def log_malicious_activity(is_active_session, reason, malicious_input, session_data):
    username = "NULL"
    coordinates = "NULL"
    country = "NULL"
    ip_address = "NULL"
    if session_data:
        coordinates = (
            "("
            + str(session_data["latitude"])
            + ", "
            + str(session_data["longitude"])
            + ")"
        )
        country = session_data["country_name"]
        ip_address = session_data["ip"]
    if is_active_session:
        username = session["username"]

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        """
INSERT INTO notifications 
(reason, malicious_input, country, coordinates, ip_address, is_active_session, ip_blocked, username)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            reason,
            malicious_input,
            country,
            coordinates,
            ip_address,
            is_active_session,
            False,
            username,
        ),
    )
    mysql.connection.commit()

@app.route("/MyWebApp/logout_other")
def logout_other_sessions():
    # Deactivate all sessions from database
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute(
        "UPDATE `logs` SET `is_active_session` = 'Inactive' WHERE `logs`.`user_id` = %s and not `ip_address`=%s",
        (
            session["user_id"],
            session["ip_address"],
        ),
    )
    mysql.connection.commit()
    # Remove session data, this will log the user out

    return redirect(url_for("activity"))









# flask-limiter verification
limiter = Limiter(app, default_limits = ["1/second"], key_func=get_remote_address)  #This works
# The old method for limiting rate for login is next line below:
# limiter.limit("1/hour")(login) which does not seem to work well enough.
limiter.limit("2/hour", login)  # This works now for limiting rate request for login page
# Able to create another one for register if possible/want.
limiter.exempt(logout)




@app.errorhandler(500)
def internalServerError(error):
    return render_template('index.html')

@app.errorhandler(404)
def pageNotFound(error):
    return render_template('index.html')

@app.errorhandler(405)
def pageNotFound(error):
    return render_template('index.html')

@app.errorhandler(429)
def ratelimit_handler(e):
    return "You have exceeded your rate-limit."





if __name__ == '__main__':
    app.run(debug=False)

    app.register_blueprint(login)
    app.register_blueprint(register)
    app.register_blueprint(home)
    app.register_blueprint(profile)
    app.register_blueprint(logout)
