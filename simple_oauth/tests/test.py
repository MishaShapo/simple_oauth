from simple_oauth import SimpleSession
sess = SimpleSession(
    client_secrets_path='secrets/secret.json',
    scope=['https://www.googleapis.com/auth/drive.readonly'],
    cache="dict")
file = sess.get_session().get('https://www.googleapis.com/drive/v3/files')
print(file.json())