import hashlib
import requests
import re

instructions = """ 
 *************************************************************************************************************
* This is a password checker that verifies whether a password has been pwned using the api.pwnedpasswords.com *
* API that belongs to https://haveibeenpwned.com. We basically check whether a password has been exposed in   *
* known public data breaches. It returns a response to let you know whether the password is compromised or    *
* not. Now, If it is not publicly compromised, the script then checks to make sure it's a strong password.    *
 *************************************************************************************************************
"""

#-------------------------------------------------------------------------------------
# Prompts the user to enter one or multiple passwords (comma-separated),
# checks each password against known data breaches using the pwned_checker function,
# and if not found in breaches, evaluates its strength using check_password_strength.
# Based on the results, it prints a security recommendation for each password.
#-------------------------------------------------------------------------------------
def run_password_check():

    args = input("Please enter your password(separate by a comma if more than 1 password): ").split(",")
    for password in args:
        count = pwned_checker(password)
        if count:
            print(f'The Password: {password} was found {count} times... you should definitely change your password!')
        else:
            strength = check_password_strength(password)
            if strength == "Weak":
                print(f'The Password: {password} was NOT found but is {strength}. We don\'t recommend using it!')
            elif strength == "Moderate":
                print(f'The Password: {password} was NOT found but is just {strength}. We recommend getting a stronger password!')
            else:
                print(f'The Password: {password} was NOT found and is {strength}. Guess you go ahead and use it!')


#-----------------------------------------------------------------------------------------
# Hashes the provided password using SHA-1, splits the hash into a 5-character prefix
# and remaining suffix (k-Anonymity model), sends the prefix to the Have I Been Pwned API,
# then compares the returned hash suffixes locally to determine how many times
# the password has appeared in known data breaches.
#-----------------------------------------------------------------------------------------
def pwned_checker(password):

    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    get_first5_chars, tail = sha1_password[:5], sha1_password[5:]
    response = api_request(get_first5_chars)
    return get_password_leak_count(response, tail)


#-------------------------------------------------------------------------------------
# Sends a GET request to the Have I Been Pwned Pwned Passwords API
# using the first 5 characters of the SHA-1 hash (k-Anonymity model).
# If the request fails (status code not 200), it raises a RuntimeError.
# Otherwise, it returns the API response object for further processing.
#-------------------------------------------------------------------------------------
def api_request(part_password):

    url = 'https://api.pwnedpasswords.com/range/' + part_password
    api_response = requests.get(url)
    if api_response.status_code != 200:
        raise RuntimeError(f'Error is showing: {api_response.status_code}, please check the api and try again')
    return api_response


#-------------------------------------------------------------------------------------
# Parses the API response containing hash suffixes and breach counts,
# compares each returned suffix with the remaining part of the user's
# SHA-1 hash, and returns the number of times the password was found
# in breaches. If no match is found, it returns 0.
#-------------------------------------------------------------------------------------
def get_password_leak_count(hash_list, password):

    hashes = (line.split(':') for line in hash_list.text.splitlines())
    for h, count in hashes:
        if h == password:
            return count
    return 0


#-------------------------------------------------------------------------------------
# Evaluates the strength of a password by assigning a score based on
# length and character variety (uppercase, lowercase, digits, special characters).
# The total score determines whether the password is classified as
# "Weak", "Moderate", or "Strong".
#-------------------------------------------------------------------------------------
def check_password_strength(password):
    score = 0

    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1

    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Moderate"
    else:
        return "Strong"

# Displays usage instructions and starts the password check process when the file is executed directly.
if __name__ == "__main__":
    print(instructions)
    run_password_check()