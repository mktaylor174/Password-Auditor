# Password-Auditor
Developed by Maggie Taylor

This contains the Python file for a password auditing/generating command-line tool. It also contains the sample txt file used to test the auditing capabilities, as well as the output files from that sample.

## Features

- Secure password generation using the Python secrets module
- Password strength analysis
- Security auditing
- Batch auditing from tab-separated txt files
- CSV and Markdown report generation

## Example Commands

python PasswordAuditor.py generate

python PasswordAuditor.py generate --length 13

python PasswordAuditor.py check 123456

python PasswordAuditor.py audit-file 2025most_used_passwords.txt
