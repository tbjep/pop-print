#!/usr/bin/python3
# -*- coding: utf-8, vim: expandtab:ts=4 -*-

import os
import re
import threading
import subprocess
import ipaddress
from urllib.parse import urlparse
import time
import requests
import uuid as Uuid
import hashlib
from requests.auth import HTTPBasicAuth
from apscheduler.schedulers.background import BackgroundScheduler
import cryptography
import secrets

from flask import Flask, request, redirect, url_for, make_response
from flask_restful import Resource, Api
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

load_dotenv()

knet_api_base_url = "https://api.k-net.dk/v2/"
print_hostname = "print.pop.dk"
print_scheme = "https"

# Get API username and password from environment variables
knet_api_username = os.environ.get("KNET_API_USERNAME")
knet_api_password = os.environ.get("KNET_API_PASSWORD")
crypt_key = os.environ.get("AES_CRYPT_KEY")
initialization_vector = os.environ.get("INITIALIZATION_VECTOR").encode()
assert crypt_key != None, "AES_CRYPT_KEY environment variable not set"

algorithm = algorithms.AES(crypt_key.encode())

mode = modes.CTR(initialization_vector)
cipher = Cipher(algorithm, mode)

UPLOAD_FOLDER = "/tmp/"
ALLOWED_EXTENSIONS = {"pdf"}
PRINTER = "default"  # Printer name from lpstat -p -d or 'default' for the system's default printer
DUPLEX_OPTIONS = {"1sided": "1Sided", "2sided": "2Sided"}
COLOR_OPTIONS = {"auto": "", "color": "Color", "grayscale": "Grayscale"}
ORIENTATION = {
    "portrait": "-o orientation-requested=3",
    "landscape": "-o orientation-requested=4",
}
SIZE = {"A4": "A4", "A3": "A3"}
RANGE_RE = re.compile("([0-9]+(-[0-9]+)?)(,([0-9]+(-[0-9]+)?))*$")

# lock to control access to variable
print_lock = threading.Lock()
LOGIN_TIME = 10 * 60

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024
api = Api(app)

print_upload_form = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>POP Print</title>
  <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.3.0/material.indigo-pink.min.css">
  <script defer src="https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.3.0/material.min.js"></script>
  <style>
    body {
      font-family: 'Roboto', sans-serif;
      background-color: #f5f5f5;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }

    form {
      background-color: #ffffff;
      padding: 20px;
      border-radius: 8px;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
    }

    p {
      margin: 0 0 20px;
    }

    #file { display: none }

    input[type="file"],
    input[type="text"],
    input[type="number"],
    input[type="submit"] {
      width: 100%;
      padding: 10px;
      margin: 8px 0;
      box-sizing: border-box;
      border: 1px solid #ccc;
      border-radius: 4px;
      font-size: 16px;
    }

    input[type="radio"] {
      margin-right: 8px;
    }

    input[type="submit"] {
      background-color: #4caf50;
      color: #fff;
      cursor: pointer;
      transition: background-color 0.3s;
    }

    input[type="submit"]:hover {
      background-color: #45a049;
    }

    .file-upload {
        margin: 0 10px 0 25px;
    }

    .file-upload input.upload {
        position: absolute;
        top: 0;
        right: 0;
        margin: 0;
        padding: 0;
        z-index: 10;
        font-size: 20px;
        cursor: pointer;
        height: 36px;
        opacity: 0;
        filter: alpha(opacity=0); 
    }

    #fileuploadurl{
        border: none;
        font-size: 12px;
        padding-left: 0;
        width: 250px; 
    }
  </style>
</head>
<body>

<form action="" method="post" enctype="multipart/form-data">
  <p>
    <h5>Upload PDF to print:</h1> <br/>
    <div class="file-upload mdl-button mdl-js-button mdl-button--raised mdl-js-ripple-effect mdl-button--accent mdl-button--colored mdl-color--green-500">
    	<span>BROWSE</span>
      	<input type="file" name="uploadedPDF" id="FileAttachment" class="upload" accept=".pdf" />
    </div>
    <input type="text" id="fileuploadurl" readonly placeholder="No file selected">
	</div>

  </p>
  <p>
    Duplex: <br/>
    <input type="radio" name="duplex" id="one-sided" value="1sided"> <label for="one-sided">One sided</label><br>
    <input type="radio" name="duplex" id="two-sided" value="2sided" checked> <label for="two-sided">Two sided</label><br>
  </p>
  <p>
    Color mode: <br/>
    <input type="radio" name="color" id="auto" value="auto" checked> <label for="auto">Auto</label><br>
    <input type="radio" name="color" id="color" value="color"> <label for="color">Color</label><br>
    <input type="radio" name="color" id="grayscale" value="grayscale"> <label for="grayscale">Grayscale</label><br>
  </p>
  <p>
    Range: <br/>
    <input type="text" name="range" placeholder="1-5,8,11-13">
  </p>
  <p>
    Size: <br/>
    <input type="radio" name="size" id="a4" value="A4" checked> <label for="a4">A4</label><br>
    <input type="radio" name="size" id="a3" value="A3"> <label for="a3">A3</label><br>
  </p>
  <p>
    Orientation: <br/>
    <input type="radio" name="orientation" id="portrait" value="portrait" checked> <label for="portrait">Portrait</label><br>
    <input type="radio" name="orientation" id="landscape" value="landscape"> <label for="landscape">Landscape</label><br>
  </p>
  <p>
    Copies: <br/>
    <input type="number" name="copies" placeholder="1">
  </p>
  <p>
    <input type="submit" value="Print" name="print">
  </p>
</form>

</body>
<script> 
document.getElementById("FileAttachment").onchange = function () {
    document.getElementById("fileuploadurl").value = document.getElementById("FileAttachment").files[0].name;
};
</script>
</html>
"""

login_form = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/icon?family=Material+Icons">
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f5f5f5;
        }

        form {
            font-family: 'Roboto', sans-serif;
            text-align: center;
            padding: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
            background-color: #ffffff;
            max-width: 400px;
            width: 100%;
        }

        h1 {
            color: #333;
            font-family: 'Roboto', sans-serif;
        }

        label {
            display: block;
            margin: 10px 0;
            color: #555;
        }

        input {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px;
        }

        input[type="submit"] {
            background-color: #4caf50;
            color: #fff;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        input[type="submit"]:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>  
    <form action="{url}" method="post">
        <h1>Login</h1>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" required><br><br>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" required><br><br>
        <input name="login" type="submit" value="Login">
    </form>
</body>
</html>
"""


def printhtml(duplex, color, page_range, orientation, size, copies, pdf, pdf_filename):
    command = ["/usr/bin/lp"]

    if PRINTER != "default":
        command.extend(["-d", PRINTER])
    else:
        command.extend(["-d", "Konica_Minolta"])
    if duplex != "none":
        command.extend(["-o", "KMDuplex=" + DUPLEX_OPTIONS[duplex]])

    if color != "auto":
        command.extend(["-o", "SelectColor=" + COLOR_OPTIONS[color]])

    if SIZE != "A4":
        command.extend(["-o", "PageSize=" + SIZE[size]])

    if len(page_range) > 0:
        command.extend(["-P", page_range])

    command.extend(ORIENTATION[orientation].split())

    if copies > 1:
        command.extend(["-n", str(copies)])

    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], pdf_filename)
    command.append(pdf_path)

    pdf.save(pdf_path)
    ret = subprocess.run(command, stderr=subprocess.PIPE)
    os.remove(pdf_path)

    if ret.returncode != 0:
        err_msg = ret.stderr.decode("UTF-8").rstrip()
        print("Printing error: {0}".format(err_msg))
        return "Printing error: {0}".format(err_msg), 500
    return None


class PrintREST(Resource):
    @staticmethod
    @app.route("/print", methods=["POST"])
    def printhtml():
        print("printing")
        pdf = request.files["uploadedPDF"]
        pdf_filename = secure_filename(pdf.filename)

        duplex = request.form["duplex"]
        color = request.form["color"]
        page_range = request.form["range"]
        orientation = request.form["orientation"]
        size = request.form["size"]
        copies = request.form["copies"]
        if copies == "":
            copies = 1
        else:
            copies = int(copies)

        if (
            duplex in DUPLEX_OPTIONS
            and pdf
            and pdf.filename.rsplit(".", 1)[1] in ALLOWED_EXTENSIONS
            and (len(page_range) == 0 or RANGE_RE.match(page_range))
            and orientation in ORIENTATION
            and copies > 0
        ):
            with print_lock:
                ret = printhtml(
                    duplex,
                    color,
                    page_range,
                    orientation,
                    size,
                    copies,
                    pdf,
                    pdf_filename,
                )
            return print_upload_form
            """ if ret is not None:
                return ret

            return 'Printing "{0}" to "{1}" with duplex "{2}" range "{3}" in "{4}" orientation {5} times...'.format(
                pdf_filename, PRINTER, duplex, page_range, orientation, copies)
        return 'Some parameters wrong: {0} {1}'.format(duplex, pdf.filename), 400 """


# redirect / to /login page
@app.route("/")
def login_and_printhtml():
    # try to get the login cookie

    login_cookie = request.cookies.get("login")

    # If cookie is set, check if it is valid
    if login_cookie != None:
        print(login_cookie)
        decryptor = cipher.decryptor()
        try:
            message_decrypted = (
                decryptor.update(bytes.fromhex(login_cookie)) + decryptor.finalize()
            )
        except cryptography.exceptions.InvalidTag:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))
        except ValueError:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))

        # Check if the cookie is valid

        try:
            print(f"Decrypted Message: {message_decrypted.decode()}")
            if time.time() - float(message_decrypted.decode()) < LOGIN_TIME:
                return print_upload_form
        except ValueError:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))
        except TypeError:
            return login_form.replace("{url}", url_for("login_and_printhtml_post"))
    # Otherwise interface is not yet logged in, Offer login

    return login_form.replace("{url}", url_for("login_and_printhtml_post"))


def login():
    login_cookie = request.cookies.get("login")

    # If cookie is set, check if it is valid
    if login_cookie != None:
        print(login_cookie)
        print("found cookie")
        decryptor = cipher.decryptor()
        try:
            message_decrypted = (
                decryptor.update(bytes.fromhex(login_cookie)) + decryptor.finalize()
           )
        except cryptography.exceptions.InvalidTag:
            pass
        except ValueError:
            pass

        # Check if the cookie is valid
        print("Decrypted cookie")

        try:
            print(f"Decrypted Message: {message_decrypted.decode()}")
            if time.time() - float(message_decrypted.decode()) < LOGIN_TIME:
                print("actually printing")
                return PrintREST.printhtml()
        except ValueError:
            pass
        except TypeError:
            pass
        # Otherwise interface is not yet logged in, Offer login
    username = request.form.get("username")
    password = request.form.get("password")
    user_response = requests.get(
        knet_api_base_url + "network/user/?username=" + username,
        auth=HTTPBasicAuth(knet_api_username, knet_api_password),
    )

    # Check if we got a 200 OK
    # If not we cannot check the login and we should fail right here
    if user_response.status_code != 200:
        print("cannot connect to knet api")
        return "login failed", 500

    # There should only be one response.
    # If less then no user was found.
    # If more then we cannot check password correctly.
    # TODO Handle lack of ['count'] key in a graceful way
    if user_response.json()["count"] != 1:
        print("user not found")
        return "Login failed", 500

    # Get password to compare. First result contain password with salt
    password_from_knet = user_response.json()["results"][0]["password"]

    # Get the password parts. Format should be sha1$[SALT]$[HASH]
    pwd_parts = password_from_knet.split("$")

    # We check that sha1 was used. If not we cannot check the password
    if pwd_parts[0] != "sha1":
        print("password wrong")
        return "Login failed", 500

    # Perform the hashing with the given password and the salt from k-net
    hash_result = hashlib.sha1(bytes(pwd_parts[1] + password, "utf-8")).hexdigest()

    # Check aginst the salt+hash stored at K-Net
    # If not OK: Stop here
    if hash_result != pwd_parts[2]:
        # Reject if login is invalid
        return "Login failed", 500

    # Get the IP address of the user
    user_ip = request.headers.get("X-Real-IP")

    # save login cookie
    encryptor = cipher.encryptor()
    message_encrypted = (
        encryptor.update(str(time.time()).encode()) + encryptor.finalize()
    )

    # print(f"Secret Key: {crypt_key}")
    # print(f"Public Initialization Vector: {initialization_vector.hex()}")
    print(f"Encrypted Message: {message_encrypted.hex()}")

    # Save the login cookie
    resp = make_response(print_upload_form)
    resp.set_cookie(
        "login",
        value=message_encrypted.hex(),
        max_age=LOGIN_TIME,
        secure=True,
        httponly=True,
    )
    print("setting cookie")

    return resp


@app.route("/", methods=["POST"])
def login_and_printhtml_post():
    # Get form name
    if "login" in request.form:
        print("logging in")
        return login()
    elif "print" in request.form:
        login_cookie = request.cookies.get("login")

        # If cookie is set, check if it is valid
        if login_cookie != None:
            print(login_cookie)
            print("found cookie")
            decryptor = cipher.decryptor()
            try:
                message_decrypted = (
                    decryptor.update(bytes.fromhex(login_cookie)) + decryptor.finalize()
                )
            except cryptography.exceptions.InvalidTag:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))
            except ValueError:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))

            # Check if the cookie is valid
            print("Decrypted cookie")

            try:
                print(f"Decrypted Message: {message_decrypted.decode()}")
                if time.time() - float(message_decrypted.decode()) < LOGIN_TIME:
                    print("actually printing")
                    return PrintREST.printhtml()
            except ValueError:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))
            except TypeError:
                return login_form.replace("{url}", url_for("login_and_printhtml_post"))
            # Otherwise interface is not yet logged in, Offer login
        return login_form.replace("{url}", url_for("login_and_printhtml_post"))
    else:
        return "Unknown form", 500


if __name__ == "__main__":
    app.run(debug=False)
