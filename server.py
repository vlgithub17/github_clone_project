import http.server
import socketserver
import urllib.parse
import requests
import os
import base64
from keys import CLIENT_ID, CLIENT_SECRET

PORT = 3000

REDIRECT_URI = 'http://localhost:3000/callback' 

class MyRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<a href="/login">Login with GitHub</a>')
        
        elif self.path == '/login':
            github_auth_url = (
                f"https://github.com/login/oauth/authorize"
                f"?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=repo"
            )
            self.send_response(302) 
            self.send_header('Location', github_auth_url)
            self.end_headers()
        
        elif self.path.startswith('/callback'):
            # Get the 'code' from the GitHub callback
            parsed_path = urllib.parse.urlparse(self.path)
            code = urllib.parse.parse_qs(parsed_path.query).get('code', [None])[0]

            if code:
                token_url = 'https://github.com/login/oauth/access_token'
                token_data = {
                    'client_id': CLIENT_ID,
                    'client_secret': CLIENT_SECRET,
                    'code': code,
                    'redirect_uri': REDIRECT_URI
                }
                headers = {'Accept': 'application/json'}

                # Request to get token
                token_response = requests.post(token_url, json=token_data, headers=headers)
                token_response_json = token_response.json()
                access_token = token_response_json.get('access_token')

                if access_token:
                    # Request to get user info
                    user_info_url = 'https://api.github.com/user'
                    user_headers = {
                        'Authorization': f'token {access_token}',
                        'Accept': 'application/vnd.github.v3+json'
                    }
                    
                    user_response = requests.get(user_info_url, headers=user_headers)

                    if user_response.status_code == 200:
                        user_data = user_response.json()
                        username = user_data.get('login')
                        print(f'Logged in user: {username}')

                        # Create a new repository
                        repo_name = 'skapi-template' 
                        create_repo_url = 'https://api.github.com/user/repos'
                        create_repo_data = {
                            'name': repo_name,
                            'private': False 
                        }
                        repo_headers = {
                            'Authorization': f'token {access_token}',
                            'Accept': 'application/vnd.github.v3+json'
                        }

                        # Create the repository
                        repo_response = requests.post(create_repo_url, json=create_repo_data, headers=repo_headers)

                        if repo_response.status_code == 201:
                            print(f'Repository "{repo_name}" created successfully!')

                            # Directory of files to update
                            files_directory = '/home/vivian-lima/Documents/vscode/getting_started_templates/getting-started-template-vanilla-html-'  # Change this to your directory containing files
                            files_to_upload = []

                            for file_name in os.listdir(files_directory):
                                file_path = os.path.join(files_directory, file_name)

                                # Only files
                                if os.path.isfile(file_path):
                                    try:
                                        with open(file_path, 'r') as file:
                                            content = file.read()
                                        files_to_upload.append((file_name, content))
                                    except Exception as e:
                                        print(f'Error reading file {file_name}: {e}')

                            # Upload each file
                            for file_name, content in files_to_upload:
                                upload_url = f'https://api.github.com/repos/{username}/{repo_name}/contents/{file_name}'

                                encoded_content = base64.b64encode(content.encode()).decode()

                                upload_data = {
                                    'message': f'Add {file_name}',
                                    'content': encoded_content
                                }

                                # Upload the file
                                upload_response = requests.put(upload_url, json=upload_data, headers=repo_headers)

                                if upload_response.status_code == 201:
                                    print(f'File "{file_name}" uploaded successfully!')
                                else:
                                    print(f'Error uploading file "{file_name}":', upload_response.json())

                            self.send_response(200)
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            self.wfile.write(b'Repository access granted and files uploaded! You can close this window.')
                        else:
                            print('Error creating repository:', repo_response.json())
                            self.send_response(500) 
                            self.send_header('Content-type', 'text/html')
                            self.end_headers()
                            self.wfile.write(b'Error creating repository. Please try again later.')
                    else:
                        print('Error fetching user info:', user_response.json())
                        self.send_response(500)
                        self.send_header('Content-type', 'text/html')
                        self.end_headers()
                        self.wfile.write(b'Error fetching user info. Please try again later.')
                else:
                    print('Error obtaining access token:', token_response_json)
                    self.send_response(500)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(b'Error obtaining access token. Please try again later.')

            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Error: No code received.')

with socketserver.TCPServer(("", PORT), MyRequestHandler) as httpd:
    print(f"Serving on port {PORT}")
    httpd.serve_forever()
