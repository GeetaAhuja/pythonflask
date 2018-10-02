from flask import jsonify,request, Response, json, session, redirect,render_template, url_for
from functools import wraps
from settings import *
import google.oauth2.credentials
import google_auth_oauthlib.flow
import jwt, datetime

books = [{
    'name':'Cat in a hat', 'price':7.99, 'isbn':7567687765435},
    {'name':'Green mat', 'price':6.99, 'isbn':645665756756}]


CLIENT_SECRETS_FILE = "./json/client_secret.json"
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']
API_SERVICE_NAME = 'drive'
API_VERSION = 'v2'


def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        print(request.headers)
        auth_header = request.headers.get('Authorization')
        if auth_header:
            auth_token = auth_header.split(" ")[1]
        else:
            auth_token = ''
        try:
            jwt.decode(auth_token,app.config['SECRET_KEY'])
            return f(*args, **kwargs)
        except:
            return jsonify({'error':'Need a valid JASON Token'})
    return wrapper


def validBookObject(bookObject):
    if('name' in bookObject and 'price' in bookObject and 'isbn' in bookObject):
        return True
    return False

def validateBookObjectforPatch(bookObject):
    props = []
    if ('name' in bookObject):
        props.append('name')
    if('price' in bookObject):
        props.append('price')
    return props



def getBook(isbn):
    book = None;
    for bk in books:
        if bk['isbn'] == isbn:
            return bk
    return book


def getBookIndex(isbn):
    i = 0
    for bk in books:
        if bk['isbn'] == isbn:
            return i
        i += 1
    return -1


def credentials_to_dict(credentials):
    return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authenticate')
def authenticate():
    print('in authenticate')
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)

    flow.redirect_uri = url_for('authenticated', _external=True)


    authorization_url, state = flow.authorization_url(
        # Enable offline access so that you can refresh an access token without
        # re-prompting the user for permission. Recommended for web server apps.
        access_type='offline',
        # Enable incremental authorization. Recommended as a best practice.
        include_granted_scopes='true')

    print(authorization_url, 'redirect uri')

    # Store the state so the callback can verify the auth server response.
    session['state'] = state

    # return flask.redirect(authorization_url)

    return redirect(authorization_url)


@app.route('/authenticated')
def authenticated():
    print('in authenticated')
    # return "True"
    state = session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('authenticated', _external=True)
    print(flow.redirect_uri)
    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session.
    # ACTION ITEM: In a production app, you likely want to save these
    #              credentials in a persistent database instead.
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    print( session['credentials'])

    return redirect(url_for('get_books1'))


@app.route('/test')
def test_api_request():
  if 'credentials' not in session:
    return redirect('authenticate')

  # Load credentials from the session.
  credentials = google.oauth2.credentials.Credentials(
      **session['credentials'])

  # drive = googleapiclient.discovery.build(
  #     API_SERVICE_NAME, API_VERSION, credentials=credentials)
  #
  # files = drive.files().list().execute()

  # Save credentials back to session in case access token was refreshed.
  # ACTION ITEM: In a production app, you likely want to save these
  #              credentials in a persistent database instead.
  session['credentials'] = credentials_to_dict(credentials)

  return jsonify({'books':books})




@app.route('/login',methods=['POST'])
def get_token():
    request_data = request.get_json()
    if(request_data['user'] == 'geeta' and request_data['pwd'] == 'pwd'):
        expiration_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=100)
        token = jwt.encode({'exp': expiration_date},app.config['SECRET_KEY'],algorithm="HS256")
        return  token;
    invalidBookMessage = {
        "error": "Invalid user credentials",
        "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
    }
    response = Response(json.dumps(invalidBookMessage), status=400, mimetype='application/json')
    return response


@app.route('/books1')
def get_books1():
    return jsonify({'books':books})

@app.route('/books')
@token_required
def get_books():
    return jsonify({'books':books})

@app.route('/books',methods=['POST'])
@token_required
def add_book():
    request_data = request.get_json()
    if validBookObject(request_data):
        new_book = {"name":request_data["name"],
                    "price": request_data["price"],
                    "isbn":request_data["isbn"]}
        books.insert(0,new_book)
        response =  Response("",status = 201,mimetype="application/json")
        response.headers["Location"] = "/books/" + str(new_book["isbn"])
        return response
    invalidBookMessage = {
        "error": "Invalid Book Object was passed in request",
        "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
    }
    response = Response(json.dumps(invalidBookMessage),status= 400,mimetype='application/json')
    return response

@app.route('/books/<int:isbn>',methods=['PUT'])
@token_required
def update_book(isbn):
    index = getBookIndex(isbn)
    if index>-1:
        request_data = request.get_json()
        new_book = {"name": request_data["name"],
                    "price": request_data["price"],
                    "isbn": isbn}
        if validBookObject(new_book):
            books[index] = new_book
            response =  Response("",status = 204,mimetype="application/json")
            response.headers["Location"] = "/books/" + str(new_book["isbn"])
            return response
        else:
            invalidBookMessage = {
                "error": "Invalid Book Object was passed in request",
                "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
            }
            response = Response(json.dumps(invalidBookMessage),status= 400,mimetype='application/json')
            return response
    else:
        invalidBookMessage = {
            "error": "Invalid isbn passed in request",
            "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
        }
        response = Response(json.dumps(invalidBookMessage), status=404, mimetype='application/json')
        return response

@app.route('/books/<int:isbn>',methods=['DELETE'])
@token_required
def delete_book(isbn):
    index = getBookIndex(isbn)
    if index>-1:
        books.pop(index)
        return Response("",status = 204)
    else:
        invalidBookMessage = {
            "error": "Invalid isbn passed in request",
            "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
        }
        response = Response(json.dumps(invalidBookMessage), status=404, mimetype='application/json')
        return response


@app.route('/books/<int:isbn>',methods=['PATCH'])
@token_required
def patch_book(isbn):
    index = getBookIndex(isbn)
    if index>-1:
        request_data = request.get_json()
        patch_props =  validateBookObjectforPatch(request_data)
        if(len(patch_props)>0):
            new_book = books[index]
            for prop in patch_props:
                new_book[prop] = request_data[prop]
            books[index] = new_book
            response =  Response("",status = 204,mimetype="application/json")
            response.headers["Location"] = "/books/" + str(new_book["isbn"])
            return response
        else:
            invalidBookMessage = {
                "error": "Invalid Book Object was passed in request",
                "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
            }
            response = Response(json.dumps(invalidBookMessage),status= 400,mimetype='application/json')
            return response
    else:
        invalidBookMessage = {
            "error": "Invalid isbn passed in request",
            "helpString": "Data passed in similar to {'name:'name,'price':0.00,'isbn':324343}"
        }
        response = Response(json.dumps(invalidBookMessage), status=404, mimetype='application/json')
        return response


@app.route('/books/<int:isbn>')
@token_required
def get_books_by_isbn(isbn):
    book = getBook(isbn)
    return jsonify({'book':book})
# if __name__ =="__main__":
    # app.run(ssl_context='adhoc')

app.run(port=5000)