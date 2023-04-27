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
    print('\t\tSocker listening on port 8090')

    print('\t\tWaiting for client request')
    # Programa gelditzen da zerbitzariak 302 erantzuna jaso arte
    client_connection, client_adress = server_socket.accept()

    # Nabigatzailetik 302 eskaera jaso
    eskaera = client_connection.recv(1024).decode()
    print('\n' + eskaera)


    # eskaeran "auth_code"-a bilatu
    lehenengo_lerroa = eskaera.split('\n')[0]
    aux_auth_code = lehenengo_lerroa.split(' ')[1]
    auth_code = aux_auth_code[7:].split('&')[0]
    print("auth_code: " + auth_code)

    # erabiltzaileari erantzun bat bueltatu
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
    datuak = {'client_id': app_key,
              'redirect_uri': redirect_uri,  # LoopBack IP address
              'response_type': 'code'}

    datuak_kodifikatuta = urllib.parse.urlencode(datuak)

    step2_uri = uri + '?' + datuak_kodifikatuta
    webbrowser.open_new(step2_uri)  # eskaera nabigatzailean zabaldu (GET metodoa erabiliko da, parametroak ?-ren ostean)

    auth_code = local_server()


    # Exchange authorization code for access token

    uri = "https://api.dropboxapi.com/oauth2/token"

    goiburuak = {'Host': 'api.dropboxapi.com',
                'Content-Type': 'application/x-www-form-urlencoded'}

    datuak = {'code': auth_code,
              'client_id': app_key,
              'client_secret': app_secret,
              'redirect_uri': redirect_uri,  # LoopBack IP address
              'grant_type': 'authorization_code'}

    erantzuna = requests.post(uri,headers=goiburuak, data=datuak, allow_redirects=False)

    status_code = erantzuna.status_code
    edukia = erantzuna.text
    edukia_json = json.loads(edukia)
    access_token = edukia_json['access_token']
    print('Status:' + str(status_code))
    print('Edukia:' + edukia)
    print('Access token:' + access_token)

    return access_token


def list_folder(access_token, cursor="", edukia_json_entries=[]):
    if not cursor:
        print("/list_folder")
        uri = "https://api.dropboxapi.com/2/files/list_folder"
        datuak = {'path': ''}
    else:
        print("/list_folder/continue")
        uri = "https://api.dropboxapi.com/2/files/list_folder/continue"
        datuak = {'cursor': cursor}

    # Call Dropbox API
    goiburuak = {'Content-Type': 'application/json',
                 'Authorization': 'Bearer ' + access_token}

    datuak_json = json.dumps(datuak)
    erantzuna = requests.post(uri, headers=goiburuak, data=datuak_json, allow_redirects=False)

    status_code = erantzuna.status_code
    edukia = erantzuna.text
    print('Status:' + str(status_code))
    print('Edukia:' + edukia)

    # See if there are more entries available. Process data.
    edukia_json = json.loads(edukia)

    for n in edukia_json['entries']:
        izena = n['name']
        print('\n' + izena)

    if edukia_json['has_more']:
        list_folder(access_token, edukia_json['cursor'])


access_token = do_oauth()
list_folder(access_token)
