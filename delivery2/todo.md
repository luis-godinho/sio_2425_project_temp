[x] when creating a session do not send password, store it in session file to decrypt private key.

[x] when creating a session use assymetric to send the info, then repo creates a symmetric key. ALL the rest will be encrypted by thys symmetric key. (key exchange)

[ ] when sending a message with session add a signature (digest of a small chunk)

[ ] the encryption and decryption of the file should be done on client side.

[x] stop asking for password client side

[ ] when sending an authenticated message send a challenge, use client private key to encrypt and public to check validity OR use the shared secret

[ ] Find a way to decrypt from the server side (maybe no encrypt the session_id)
