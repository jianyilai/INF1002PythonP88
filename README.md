# INF1002 Python P8-8 Phishing Email Detection System
This system allows the user to input 3 thing from an email, SENDER, SUBJECT and BODY. The program will then analyze the contents and determine whether the email is either SAFE, SUSPICIOUS or PHISHING.
## Key Features
- Whitelist Check
- Keyword Detection
- Keyword Position Scoring
- Edit Distance Check
- Suspicious URL Detection
- Final Risk Scoring
## Getting started
Download and unzip the project folder or clone it using Git:
```
git clone https://github.com/jianyilai/INF1002PythonP88.git
```
If the .venv folder does not already exist, create one by running:
```
python -m venv .venv
```
To activate the virtual environment run:
```
.venv\Scripts\activate
```
Install all the required packages using:
```
pip install -r requirements.txt
```
Start the flask appliction by running:
```
python app.py
```
