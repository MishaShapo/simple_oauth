from simple_oauth import SimpleSession
sess = SimpleSession(client_secrets_path='../../secrets/secrets.json',scope=['https://www.googleapis.com/auth/drive.readonly'])
file = sess.get_session().get('https://www.googleapis.com/drive/v3/files')
print(file.json())
