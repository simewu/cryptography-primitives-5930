import os
import sys
import re
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import padding as sym_padding

# Configuration class to store file names and directory paths for the application
class Configuration:
	directory = 'outputs'
	public_key_file_name = os.path.join(directory, 'public_key.pem')
	private_key_file_name = os.path.join(directory, 'private_key.pem')
	encryption_file_name = os.path.join(directory, 'encrypted_file.enc')
	decryption_file_name = os.path.join(directory, 'decrypted_file.txt')
	signature_file_name = os.path.join(directory, 'signature.txt')

# Main application function to display the menu and handle user input
def main():
	if not os.path.exists(Configuration.directory):
		print(
			f'Creating directory {Configuration.directory} for output files.')
		os.makedirs(Configuration.directory, exist_ok=True)

	while True:
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
		clear_screen()

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
			decrypt_file(Configuration.encryption_file_name)
			print(
				f'File decrypted successfully as {Configuration.decryption_file_name}')
			print()
			print('Its contents are: ')
			with open(Configuration.decryption_file_name, 'rb') as f:
				print(f.read())

		elif choice in ['2', '4', '5']:
			if not os.path.exists(Configuration.public_key_file_name) or not os.path.exists(Configuration.private_key_file_name):
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
				with open(Configuration.encryption_file_name, 'rb') as f:
					print(f.read())

			elif choice == '4':
				sign_file(file_name)
				print(f'Signature generated successfully as {file_name}')
				print()
				print('Its contents are: ')
				with open(Configuration.signature_file_name, 'rb') as f:
					print(f.read())

			elif choice == '5':
				verify_signature(file_name, Configuration.signature_file_name)

		else:
			print('Exiting application.')
			break

		print()

# Clear the text console screen
def clear_screen():
	os.system('cls' if os.name == 'nt' else 'clear')

# Generate an RSA keypair and save it to files in the output directory
def generate_rsa_keypair():
	try:
		private_key = rsa.generate_private_key(
			public_exponent=65537, key_size=2048)
		public_key = private_key.public_key()

		# Ensuring the output directory exists
		os.makedirs(Configuration.directory, exist_ok=True)

		# Save the private key
		with open(Configuration.private_key_file_name, 'wb') as f:
			f.write(private_key.private_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PrivateFormat.PKCS8,
					encryption_algorithm=serialization.NoEncryption()
					))

		# Save the public key
		with open(Configuration.public_key_file_name, 'wb') as f:
			f.write(public_key.public_bytes(
					encoding=serialization.Encoding.PEM,
					format=serialization.PublicFormat.SubjectPublicKeyInfo
					))
		print('RSA keypair generated and saved successfully.')
	except Exception as e:
		print(f'Failed to generate RSA keypair: {e}')

# Class to handle AES padding for encryption and decryption
class AESPadding:
	@staticmethod
	def pad(data):
		padder = sym_padding.PKCS7(128).padder()
		return padder.update(data) + padder.finalize()

	@staticmethod
	def unpad(padded_data):
		unpadder = sym_padding.PKCS7(128).unpadder()
		return unpadder.update(padded_data) + unpadder.finalize()

# Encrypt a file using an RSA public key and AES-256
def encrypt_file(file_name):
	try:
		with open(Configuration.public_key_file_name, 'rb') as key_file:
			public_key_pem = key_file.read()
		public_key = serialization.load_pem_public_key(
			public_key_pem, backend=default_backend())

		aes_key = os.urandom(32)  # AES-256
		iv = os.urandom(16)

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
						backend=default_backend())
		encryptor = cipher.encryptor()

		with open(file_name, 'rb') as f:
			plaintext = f.read()

		padded_plaintext = AESPadding.pad(plaintext)

		ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

		encrypted_aes_key = public_key.encrypt(
			aes_key,
			padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

		with open(Configuration.encryption_file_name, 'wb') as f:
			f.write(encrypted_aes_key + iv + ciphertext)
		print(
			f'File encrypted successfully as {Configuration.encryption_file_name}')
	except Exception as e:
		print(f'Encryption failed: {e}')

# Decrypt a file using an RSA private key and AES-256
def decrypt_file(file_name):
	try:
		with open(Configuration.private_key_file_name, 'rb') as key_file:
			private_key_pem = key_file.read()
		private_key = serialization.load_pem_private_key(
			private_key_pem, password=None, backend=default_backend())

		with open(file_name, 'rb') as f:
			file_content = f.read()

		encrypted_aes_key = file_content[:private_key.key_size // 8]
		iv = file_content[private_key.key_size //
						  8:private_key.key_size // 8 + 16]
		ciphertext = file_content[private_key.key_size // 8 + 16:]

		aes_key = private_key.decrypt(
			encrypted_aes_key,
			padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

		cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),
						backend=default_backend())
		decryptor = cipher.decryptor()
		padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

		plaintext = AESPadding.unpad(padded_plaintext)

		with open(Configuration.decryption_file_name, 'wb') as f:
			f.write(plaintext)
		print(
			f'File decrypted successfully as {Configuration.decryption_file_name}')
	except Exception as e:
		print(f'Decryption failed: {e}')

# Sign a file using an RSA private key and save the signature to a file
def sign_file(file_name):
	try:
		with open(Configuration.private_key_file_name, 'rb') as key_file:
			private_key_pem = key_file.read()
		private_key = serialization.load_pem_private_key(
			private_key_pem, password=None, backend=default_backend())

		with open(file_name, 'rb') as f:
			data = f.read()

		signature = private_key.sign(
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
						salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())

		with open(Configuration.signature_file_name, 'wb') as f:
			f.write(signature)
		print(
			f'Signature generated successfully as {Configuration.signature_file_name}')
	except Exception as e:
		print(f'Error signing file: {e}')

# Verify the signature of a file using an RSA public key and a signature file
def verify_signature(file_name, signature_file):
	try:
		with open(Configuration.public_key_file_name, 'rb') as key_file:
			public_key_pem = key_file.read()
		public_key = serialization.load_pem_public_key(
			public_key_pem, backend=default_backend())

		with open(file_name, 'rb') as f:
			data = f.read()
		with open(signature_file, 'rb') as f:
			signature = f.read()

		public_key.verify(
			signature,
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
						salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256())
		print('Signature was successfully verified and is valid.')
	except InvalidSignature:
		print('Signature is NOT valid.')
	except Exception as e:
		print(f'Error verifying signature: {e}')

# Given a regular expression, list the files that match it, and ask for user input
def selectFile(regex, subdirs=False, multiSelect=False):
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
def listFiles(regex='.*', directory='', subdirs=True):
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
