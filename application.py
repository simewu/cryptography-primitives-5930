import os
import sys
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding as sym_padding

# File output names as global variables
directory = 'outputs'
public_key_file_name = os.path.join(directory, 'public_key.pem')
private_key_file_name = os.path.join(directory, 'private_key.pem')
encryption_file_name = os.path.join(directory, 'encrypted_file.enc')
decryption_file_name = os.path.join(directory, 'decrypted_file.txt')
signature_file_name = os.path.join(directory, 'signature.txt')
if not os.path.exists(directory):
	print(f'Creating directory {directory} for output files.')
	os.makedirs(directory)

# Main application
def main():
	while True:
		# Clear the screen
		
		print()
		print('Please select an operation: ')
		print('  1 - Generate Keypair')
		print('  2 - Encrypt File')
		print('  3 - Decrypt File')
		print('  4 - Generate File Signature')
		print('  5 - Verify File Signature')
		print('  6 - Exit Application')
		print()
		choice = input('Your selection: ')
		os.system('cls' if os.name == 'nt' else 'clear')

		if choice == '1': print('You selected "Generate Keypair".')
		elif choice == '2': print('You selected "Encrypt File".')
		elif choice == '3': print('You selected "Decrypt File".')
		elif choice == '4': print('You selected "Generate File Signature".')
		elif choice == '5': print('You selected "Verify File Signature".')
		else: print('You selected "Exit Application".')
		print()
		print()

		if choice == '1':
			generate_rsa_keypair()
			print('Generated:')
			print('  -  private_key.pem')
			print('  -  public_key.pem')
			print('RSA keypair generated successfully.')
			
		elif choice == '3':
			decrypt_file(encryption_file_name)
			print(f'File decrypted successfully as {decryption_file_name}')
			print()
			print('Its contents are: ')
			with open(decryption_file_name, 'rb') as f:
				print(f.read())

		elif choice in ['2', '4', '5']:
			if not os.path.exists(public_key_file_name) or not os.path.exists(private_key_file_name):
				print('RSA keypair not found. Please generate a keypair first.')
				continue

			file_name = selectFile(r'.*', False)
			if not file_name:
				continue
			print(f'You selected "{file_name}".')

			if choice == '2':
				encrypt_file(file_name)
				print(f'File encrypted successfully as {file_name}')
				print()
				print('Its contents are: ')
				with open(encryption_file_name, 'rb') as f:
					print(f.read())

			elif choice == '4':
				sign_file(file_name)
				print(f'Signature generated successfully as {file_name}')
				print()
				print('Its contents are: ')
				with open(signature_file_name, 'rb') as f:
					print(f.read())

			elif choice == '5':
				verify_signature(file_name, signature_file_name)

		else:
			print('Exiting application.')
			break

		print()

# Generate an RSA keypair and save it to files
def generate_rsa_keypair():
	private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
	public_key = private_key.public_key()

	# Save the private key
	with open(private_key_file_name, 'wb') as f:
		f.write(private_key.private_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PrivateFormat.PKCS8,
			encryption_algorithm=serialization.NoEncryption()
		))

	# Save the public key
	with open(public_key_file_name, 'wb') as f:
		f.write(public_key.public_bytes(
			encoding=serialization.Encoding.PEM,
			format=serialization.PublicFormat.SubjectPublicKeyInfo
		))

# Function to pad plaintext for AES encryption
def pad(data):
	padder = sym_padding.PKCS7(128).padder()  # 128 bit = 16 byte block size
	padded_data = padder.update(data) + padder.finalize()
	return padded_data

# Function to unpad plaintext after AES decryption
def unpad(padded_data):
	unpadder = sym_padding.PKCS7(128).unpadder()
	data = unpadder.update(padded_data) + unpadder.finalize()
	return data

# Encrypt a file using an RSA public key
def encrypt_file(file_name):
	try:
		with open(public_key_file_name, 'rb') as key_file:
			public_key_pem = key_file.read()
		public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

		aes_key = os.urandom(32)  # AES-256
		iv = os.urandom(16)

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
		encryptor = cipher.encryptor()

		with open(file_name, 'rb') as f:
			plaintext = f.read()
		
		padded_plaintext = pad(plaintext)  # Pad the plaintext before encryption

		ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

		encrypted_aes_key = public_key.encrypt(
			aes_key,
			padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

		with open(encryption_file_name, 'wb') as f:
			f.write(encrypted_aes_key + iv + ciphertext)
		print(f'File encrypted successfully as {encryption_file_name}')
	except Exception as e:
		print(f'Error encrypting file: {e}')

# Decrypt a file using an RSA private key
def decrypt_file(file_name):
	try:
		with open(private_key_file_name, 'rb') as key_file:
			private_key_pem = key_file.read()
		private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

		with open(file_name, 'rb') as f:
			file_content = f.read()

		encrypted_aes_key = file_content[:private_key.key_size // 8]
		iv = file_content[private_key.key_size // 8:private_key.key_size // 8 + 16]
		ciphertext = file_content[private_key.key_size // 8 + 16:]

		aes_key = private_key.decrypt(
			encrypted_aes_key,
			padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
		decryptor = cipher.decryptor()
		padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

		plaintext = unpad(padded_plaintext)  # Unpad the decrypted plaintext

		with open(decryption_file_name, 'wb') as f:
			f.write(plaintext)
		print(f'File decrypted successfully as {decryption_file_name}')
	except Exception as e:
		print(f'Error decrypting file: {e}')

# Sign a file using an RSA private key
def sign_file(file_name):
	try:
		with open(private_key_file_name, 'rb') as key_file:
			private_key_pem = key_file.read()
		private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

		with open(file_name, 'rb') as f:
			data = f.read()

		signature = private_key.sign(
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())

		with open(signature_file_name, 'wb') as f:
			f.write(signature)
		print(f'Signature generated successfully as {signature_file_name}')
	except Exception as e:
		print(f'Error signing file: {e}')

# Verify the signature of a file using an RSA public key
def verify_signature(file_name, signature_file):
	try:
		with open(public_key_file_name, 'rb') as key_file:
			public_key_pem = key_file.read()
		public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

		with open(file_name, 'rb') as f:
			data = f.read()
		with open(signature_file, 'rb') as f:
			signature = f.read()

		public_key.verify(
			signature,
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())
		print('Signature was successfully verified and is valid.')
	except InvalidSignature:
		print('Signature is NOT valid.')
	except Exception as e:
		print(f'Error verifying signature: {e}')

# Given a regular expression, list the files that match it, and ask for user input
def selectFile(regex, subdirs = False, multiSelect = False):
	try:
		files = []
		compiledRegex = re.compile(regex)
		if subdirs:
			for dirPath, _, fileNames in os.walk('.'):
				for file in fileNames:
					path = os.path.normpath(os.path.join(dirPath, file))
					if compiledRegex.match(path):
						files.append(path)
		else:
			for file in os.listdir(os.curdir):
				fullPath = os.path.join(os.curdir, file)
				if os.path.isfile(fullPath) and compiledRegex.match(file):
					files.append(file)

		if not files:
			print(f'No files were found that match "{regex}"\n')
			return []

		print('List of files:')
		for i, file in enumerate(files):
			print(f'  File {i + 1}  -  {file}')
		print()

		selectionPrompt = 'Please select files (e.g., 1,3,5): ' if multiSelect else 'Please select a file: '
		if multiSelect:
			selectedFiles = []
			while not selectedFiles:
				input_str = input(selectionPrompt)
				selections = re.split(r',\s*|\s+', input_str)

				for selection in selections:
					try:
						index = int(selection) - 1
						if 0 <= index < len(files):
							selectedFiles.append(files[index])
					except ValueError:
						pass

				if not selectedFiles:
					print('Invalid selection, please try again.')

			return selectedFiles
		else:
			while True:
				selection = int(input(selectionPrompt))
				if 1 <= selection <= len(files):
					return files[selection - 1]
	except KeyboardInterrupt:
		print("\nOperation cancelled by user.")
		sys.exit()

# Lists files in a directory matching a given regex, optionally including subdirectories
def listFiles(regex = '.*', directory = '', subdirs = True):
	files = []
	if subdirs:
		for root, _, fileNames in os.walk(directory):
			for fileName in fileNames:
				filePath = os.path.join(root, fileName)
				if re.match(regex, fileName):
					files.append(filePath)
	else:
		path = os.path.abspath(directory)
		files = [os.path.join(path, file) for file in os.listdir(path) 
				 if os.path.isfile(os.path.join(path, file)) and re.match(regex, file)]
	return files

if __name__ == '__main__':
	main()
