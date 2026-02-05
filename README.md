#Password Manager Application

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flet](https://img.shields.io/badge/Built%20with-Flet-purple)

--Description--

A simple application written in python script where you can store your passwords. Each password is related to one account(e.g. facebook,gmail,steam etc.).
However, to enter the application you will need to enter the 'key', which is a password that you enter the first time you open the application.
The logic behind this is, instead of having to keep track of all the different passwords you just remember the key and the rest of your passwords
are stored in the application.

--How it works--

Encryption:
  Passwords are encrypted using the AES encryption algorithm with Cipher Block Chaining (CBC) mode.
  The key is derived from the user's input using SHA-256 hashing.
  Each password is encrypted with this key.

Functionality:

  Users can add new passwords, overwrite existing passwords, or decrypt stored passwords.
  Passwords are associated with specific websites or services, allowing for easy retrieval.

File Handling:

  The program reads and writes data to files (password.txt, login.txt, backup.txt) for storing passwords, login information, and backup data.
  It checks for the existence of these files and creates them if they don't exist.

Security:

  Passwords are never stored in plaintext.
  Encryption keys are derived from user input, adding an extra layer of security.
  Error handling is implemented to handle various scenarios gracefully.

--Create exe.--

To create the executable file simply navigate to the gui_modern.py directory and execute in cmd

	python -m PyInstaller --onefile -w --name "Password Manager" --distpath "./Cool name folder Folder" gui_modern.py
