# PRODIGY_CS_03
I have built a tool that assesses the strength of a password based on criteria such as length, presence of uppercase and lowercase letters, numbers, and special characters. And it provides feedback to users on the password's strength.(Using Python ) 
So, Here is my Project check below:

import re

def check_password_complexity(password):
    # Define regex patterns for various criteria
    length_pattern = r'.{8,}'  # Minimum length of 8 characters
    uppercase_pattern = r'[A-Z]'
    lowercase_pattern = r'[a-z]'
    digit_pattern = r'\d'
    special_char_pattern = r'[!@#$%^&*()-+=]'
    
    # Check if password meets each criteria
    length_check = bool(re.match(length_pattern, password))
    uppercase_check = bool(re.search(uppercase_pattern, password))
    lowercase_check = bool(re.search(lowercase_pattern, password))
    digit_check = bool(re.search(digit_pattern, password))
    special_char_check = bool(re.search(special_char_pattern, password))

    # Calculate score based on the number of criteria met
    score = sum([length_check, uppercase_check, lowercase_check, digit_check, special_char_check])

    # Provide feedback based on the score
    if score == 5:
        return "Password is very strong"
    elif score >= 3:
        return "Password is strong"
    elif score >= 2:
        return "Password is moderate"
    else:
        return "Password is weak"

def main():
    password = input("Enter your password: ")
    complexity_feedback = check_password_complexity(password)
    print(complexity_feedback)

if __name__ == "__main__":
    main()
