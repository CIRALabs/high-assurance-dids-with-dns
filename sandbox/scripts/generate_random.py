

import random
import string

def generate_identifier():
    # Generate a random alphanumeric string of length 18
    identifier = ''.join(random.choices(string.ascii_letters + string.digits, k=18))
    
    # Calculate the checksum
    checksum = sum(ord(c) for c in identifier) % 100
    
    # Append the checksum to the identifier
    identifier += str(checksum).zfill(2)
    
    return identifier

def verify_checksum(identifier):
    # Extract the identifier without the last two digits (checksum)
    identifier_without_checksum = identifier[:-2]
    
    # Calculate the checksum of the identifier without the checksum
    expected_checksum = sum(ord(c) for c in identifier_without_checksum) % 100
    
    # Extract the provided checksum from the identifier
    provided_checksum = int(identifier[-2:])
    
    # Check if the provided checksum matches the expected checksum
    return expected_checksum == provided_checksum

# Example usage
identifier = generate_identifier()
print(identifier)
result = verify_checksum('j7hd6En2KoWr7OnIE978')
print(result)