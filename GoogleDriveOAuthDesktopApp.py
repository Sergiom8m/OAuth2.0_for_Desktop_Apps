import requests
import urllib
import webbrowser
import socket
import json

print("###################################")
print("OAuth 2.0 for Mobile & Desktop Apps")
print("###################################")
# https://developers.google.com/identity/protocols/oauth2/native-app

print("\nPrerequisites on Google Cloud Console")
# https://developers.google.com/identity/protocols/oauth2/native-app#prerequisites

print("\tEnable APIs for your project")
# https://developers.google.com/identity/protocols/oauth2/native-app#enable-apis

print("\tIdentify access scopes")
# https://developers.google.com/identity/protocols/oauth2/native-app#identify-access-scopes
scope = "https://www.googleapis.com/auth/drive.readonly"  # See and download all your Google Drive files

print("\tCreate authorization credentials")
# https://developers.google.com/identity/protocols/oauth2/native-app#creatingcred
client_id = ""
client_secret = ""

print("\tConfigure OAuth consent screen")
print("\t\tAdd access scopes and test users")

print("\nObtaining OAuth 2.0 access tokens")
# https://developers.google.com/identity/protocols/oauth2/native-app#obtainingaccesstokens
print("\tStep 2: Send a request to Google's OAuth 2.0 server")
# https://developers.google.com/identity/protocols/oauth2/native-app#step-2:-send-a-request-to-googles-oauth-2.0-server
base_uri = "https://accounts.google.com/o/oauth2/v2/auth"

data = {'client_id': client_id,
        'redirect_uri': 'http://127.0.0.1:8090',  # Loopback IP address
        'response_type': 'code',
        'scope': scope}
coded_data = urllib.parse.urlencode(data)
step2_uri = base_uri + '?' + coded_data
print("\t" + step2_uri)
webbrowser.open_new(step2_uri)  # Open the request on the explorer (GET is the predetermined method)
print("\n\tStep 3: Google prompts user for consent")

# print("\n\tStep 4: Handle the OAuth 2.0 server response")
# https://developers.google.com/identity/protocols/oauth2/native-app#handlingresponse
# 8090. portuan entzuten dagoen zerbitzaria sortu
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8090))
server_socket.listen(1)
print("\t\tSocket listening on port 8090")

print("\t\tWaiting for client requests...")
# In the following line the program stops until the server receives 302 requests.
client_connection, client_address = server_socket.accept()

# Receive 302 response from the explorer
request = client_connection.recv(1024).decode()
print("\t\tThe next request has been received from the explorer:")
print("\n" + request)

# Search for the auth_code on the request
first_line = request.split('\n')[0]
aux_auth_code = first_line.split(' ')[1]
auth_code = aux_auth_code[7:].split('&')[0]
print("auth_code: " + auth_code)

# Send a response to the user
http_response = """\
HTTP/1.1 200 OK

<html>
<head><title>Proba</title></head>
<body>
The authentication flow has completed. Close this window.
</body>
</html>
"""
client_connection.sendall(str.encode(http_response))
client_connection.close()
server_socket.close()

print("\n\tStep 5: Exchange authorization code for refresh and access tokens")
# https://developers.google.com/identity/protocols/oauth2/native-app#exchange-authorization-code
uri = "https://oauth2.googleapis.com/token"
headers = {'Host': 'oauth2.googleapis.com',
           'Content-Type': 'application/x-www-form-urlencoded'}
data = {'client_id': client_id,
        'client_secret': client_secret,
        'code': auth_code,
        'grant_type': 'authorization_code',
        'redirect_uri': 'http://127.0.0.1:8090'}
coded_data = urllib.parse.urlencode(data)
headers['Content-Length'] = str(len(coded_data))
response = requests.post(uri, headers=headers, data=coded_data, allow_redirects=False)
status = response.status_code
print("\t\tStatus: " + str(status))

# Google responds to this request by returning a JSON object
# that contains a short-lived access token and a refresh token.
content = response.text
print("\t\tContent:")
print("\n" + content)
content_json = json.loads(content)
access_token = content_json['access_token']
print("\naccess_token: " + access_token)

input("\nThe authentication flow has completed. Close browser window and press enter to continue...")

print("\nCalling Google APIs")
# https://developers.google.com/identity/protocols/oauth2/native-app#callinganapi
# Drive API --> Files --> list --> https://developers.google.com/drive/api/v3/reference/files/list
uri = 'https://www.googleapis.com/drive/v3/files'
headers = {'Host': 'www.googleapis.com',
           'Authorization': 'Bearer ' + access_token}
response = requests.get(uri, headers=headers, allow_redirects=False)
status = response.status_code
print("\tStatus: " + str(status))
content = response.text
print("\tEdukia:")
print(content)
input("Press enter to process JSON data structure...")
content_json = json.loads(content)
for each in content_json['files']:
    print(each['name'])

# If the list has some pages, get the data from the next pages
if 'nextPageToken' in content_json:
    data = {'pageToken': content_json['nextPageToken'], }
    coded_data = urllib.parse.urlencode(data)
    response = requests.get(uri + '?' + coded_data,
                            headers=headers, allow_redirects=False)
    status = response.status_code
    print("\tStatus: " + str(status))
    content = response.text
    print("\tEdukia:")
    print(content)
    input("Press enter to process JSON data structure...")
    content_json = json.loads(content)
    for each in content_json['files']:
        print(each['name'])
