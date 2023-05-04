import requests
import urllib
import webbrowser
import socket
import json

app_key = "ascjwcamtdbviac"
app_secret = "gwwma53ln9iar0x"
server_addr = "localhost"
server_port = "8090"
redirect_uri = "http://" + server_addr + ":" + str(server_port)


def local_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8090))
    server_socket.listen(1)
    print('Socket listening on port 8090')

    print('Waiting for client request')
    # In the following line the program stops until the server receives 302 requests.
    client_connection, client_adress = server_socket.accept()

    # Receive 302 response from the explorer
    request = client_connection.recv(1024).decode()
    # print('\n' + request)

    # Search for the auth_code on the request
    first_line = request.split('\n')[0]
    aux_auth_code = first_line.split(' ')[1]
    auth_code = aux_auth_code[7:].split('&')[0]
    print("Auth_code: " + auth_code)

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

    return auth_code


def do_oauth():
    # Authorization
    uri = "https://www.dropbox.com/oauth2/authorize"
    data = {'client_id': app_key,
            'redirect_uri': redirect_uri,  # LoopBack IP address
            'response_type': 'code'}

    coded_data = urllib.parse.urlencode(data)
    uri = uri + '?' + coded_data
    webbrowser.open_new(uri)  # Open the request on the explorer (GET is the predetermined method)
    auth_code = local_server()

    # Exchange authorization code for access token
    uri = "https://api.dropboxapi.com/oauth2/token"
    headers = {'Host': 'api.dropboxapi.com',
               'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'code': auth_code,
            'client_id': app_key,
            'client_secret': app_secret,
            'redirect_uri': redirect_uri,  # LoopBack IP address
            'grant_type': 'authorization_code'}

    response = requests.post(uri, headers=headers, data=data, allow_redirects=False)

    status_code = response.status_code
    content = response.text
    content_json = json.loads(content)
    access_token = content_json['access_token']
    # print('Status:' + str(status_code))
    # print('Content:' + content)
    print('Access token:' + access_token)

    return access_token


def list_folder(access_token, cursor=""):
    if not cursor:
        print("/list_folder")
        uri = "https://api.dropboxapi.com/2/files/list_folder"
        data = {'path': '', 'recursive': True}
    else:
        print("/list_folder/continue")
        uri = "https://api.dropboxapi.com/2/files/list_folder/continue"
        data = {'cursor': cursor}

    # Call Dropbox API
    headers = {'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + access_token}

    data_json = json.dumps(data)
    response = requests.post(uri, headers=headers, data=data_json, allow_redirects=False)

    status_code = response.status_code
    content = response.text
    # print('Status:' + str(status_code))
    # print('Content:' + content)

    # See if there are more entries available. Process data.
    content_json = json.loads(content)
    for n in content_json['entries']:
        name = n['name']
        print('\n' + name)

    if content_json['has_more']:
        list_folder(access_token, content_json['cursor'])


access_token = do_oauth()
list_folder(access_token)
