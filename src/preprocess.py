import pandas as pd
import re

file_path = r"data\raw\Nigerian_Fraud.csv"
# Load the dataset
df = pd.read_csv(file_path, encoding='utf-8')

# Remove missing value and whitespace
df = df.dropna(subset=['sender', 'subject', 'body'])
for col in ['sender', 'subject', 'body']:
    df[col] = df[col].astype(str).str.strip()

# check whether the sender column contains valid email addresses
def check_sender_email(text): 
    # extract all valid email addresses
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    found = re.findall(email_pattern, text)
    return found[0] if found else text

df['sender'] = df['sender'].apply(check_sender_email)

df = df.reset_index(drop=True)

# Save cleaned data to data/processed folder
processed_path = r"data\processed\Nigerian_Fraud_cleaned.csv"
df.to_csv(processed_path, index=False)
print(f"Cleaned data saved to {processed_path}")