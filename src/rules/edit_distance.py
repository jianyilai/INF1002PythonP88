import csv

def levenshtein_distance(s1, s2):
    # Initialize a matrix (dp table) to store distances
    rows = len(s1) + 1
    cols = len(s2) + 1
    dp = [[0 for _ in range(cols)] for _ in range(rows)]

    # Initialize the first row and column
    for i in range(rows):
        dp[i][0] = i
    for j in range(cols):
        dp[0][j] = j

    # Populate the dp table
    for i in range(1, rows):
        for j in range(1, cols):
            if s1[i-1] == s2[j-1]:
                cost = 0  # No cost if characters match
            else:
                cost = 1  # Cost of 1 for substitution

            # Calculate the minimum of insertion, deletion, or substitution
            dp[i][j] = min(
                dp[i-1][j] + 1,      # Deletion
                dp[i][j-1] + 1,      # Insertion
                dp[i-1][j-1] + cost  # Substitution
            )

    # The bottom-right cell contains the Levenshtein distance
    return dp[rows-1][cols-1]

safe_list = []

file_path = r"INF1002PythonP88\dictionary\safedomain.txt"
with open(file_path, newline='') as inputfile:
    for row in csv.reader(inputfile):
        safe_list.append(row)

domain = "outsee.pr"

for safe in safe_list: #compare the suspicious domain with each safe domain
    distance = levenshtein_distance(domain, safe[0])
    if distance < 1: # if there are no differences
        print(f"{domain} is a safe domain.") 
        break
