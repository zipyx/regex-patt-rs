use bcrypt::{verify, hash_with_salt, DEFAULT_COST, HashParts};
use regex::Regex;
use rustrict::CensorStr;
use unicode_normalization::UnicodeNormalization;
use rand::Rng;

use super::util::{read_file_hashset, read_file};

/// Struct password object
pub struct Password_Object {
    // username: String,
    validity: bool,
    message: String,
}

/// Generate salt for password hash function
pub fn generate_salt() -> [u8; 16] {

    // Generate random salt, to be stored in database column
    let mut salt: [u8; 16] = [0; 16];
    rand::thread_rng().fill(&mut salt);
    salt
}

/// Compare password with hash to verify if it is correct
pub fn compare_password(password: String, hash: String) -> bool {
    verify(password, hash.to_string().as_str()).unwrap()
}

/// Generate a suitable password from plain text 
pub fn generate_password(password: String) -> String {

    const PEPPER: &str = "PkCt&farjdWL2&WTaoddA2u7S4hfxDkbtNFxxU92";
    let result = password + PEPPER;
    result
}

/// Hash function that takes in a single input being the password 
/// and returns a string
pub fn hash_password(password: String) -> String {

    let salt = generate_salt();
    let generated_password = generate_password(password.clone());

    // Convert extended password to bytes and begin hashing with salt
    let hash = hash_with_salt(generated_password.clone(), DEFAULT_COST, salt).unwrap();

    // Confirm hash
    let result = compare_password(generated_password, hash.to_string());
    println!("Hash result: {}", result);

    hash.to_string().clone()
}


/// Verify Password by taking in a single parameter being that of password 
/// - passowrd : &str
pub fn verify_password(password: &str) -> Password_Object {

    // check password length
        let check_password_length = password.len() >= 8 && password.len() <= 64;

        // 2 - Check passwords against a list of known weak passwords / blacklist
        let weak_passwords = read_file_hashset("weakpasswords.txt");
        let breached_passwords = read_file_hashset("breachedpasswords.txt");

        // if 1st rule is met, check for second rule and return true if both are met
        if check_password_length {
            if breached_passwords.contains(password) {

                // Password found in blacklist
                return Password_Object {
                    validity: false,
                    message: "Password compromised, found online".to_string(),
                }
            } else if weak_passwords.contains(password) {

                // Password not found in blacklist and meets length requirements
                return Password_Object {
                    validity: false,
                    message: "Password is weak, use another.".to_string(),
                }
            } else {

                return Password_Object {
                    validity: true,
                    message: "Password is secure".to_string(),
                }
            }
        } else {

            // Password does not meet length requirements
            return Password_Object {
                validity: false,
                message: "Pasword must be at least 8 characters".to_string(),
            }
        }
}

/// Verifying username with regex + unicode normalization
pub fn verify_username(username: &str) -> bool {
    
    // normalize the username
    let normalized = username.nfkd().nfkc().nfd().filter(|c| c.is_alphanumeric()).collect::<String>();

    // check if string is first accepted by first regex
    let re = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();

    if re.is_match(normalized.as_str()) {
        // println!("Username {} normalized as best as possible, previously {}", normalized, username);
        return regex_pattern_match(normalized.as_str())
    }

    regex_pattern_match(normalized.as_str())
}

/// Regex pattern matching for username, this is very slow do not use this.
pub fn regex_pattern_match(username: &str) -> bool {
    let regex_patterns = read_file("regex.txt");
    for pattern in regex_patterns {
        let re = Regex::new(pattern.as_str()).unwrap();
        if re.is_match(username) {
            println!("Username {} | doesn't meet requirements", username, );
            return false;
        }
    }
    true
}

/// Censore username checker - not really needed but good 
/// modulation of code.
pub fn censor_username(username: &str) -> bool {

    // impl rate limit
    // (burst, rate, seconds)
    // let ratelimiter = Ratelimiter::new(1, 1, 1); //  1/s with no burst

    if username.is_inappropriate() {
        println!("Username {} | is inappropriate", username);
        return false
    }

    username.is_inappropriate()
}
