def check_password_complexity(password, length_config=12, uppercase_config=True, lowercase_config=True, digits_config=True, special_config=True) -> bool:
    
    if len(password) < length_config:
        return False
    if uppercase_config and not any(c.isupper() for c in password):
        return False
    if lowercase_config and not any(c.islower() for c in password):
        return False
    if digits_config and not any(c.isdigit() for c in password):
        return False
    if special_config and not any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?/' for c in password):
        return False
    return True

def generate_secure_password(length=12):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/'
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if check_password_complexity(password):
            return password


