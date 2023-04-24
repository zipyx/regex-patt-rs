use bcrypt::{verify, hash_with_salt, DEFAULT_COST};
use regex::Regex;
use rustrict::CensorStr;
use unicode_normalization::UnicodeNormalization;
use rand::Rng;

use super::util::{read_file_hashset, read_file};

/// Struct password object
struct Password_Object {
    // username: String,
    validity: bool,
    message: String,
}

fn generate_salt() -> [u8; 16] {

    // Generate random salt, to be stored in database column
    let mut salt: [u8; 16] = [0; 16];
    rand::thread_rng().fill(&mut salt);
    salt
}

fn hash_password(password: String) -> String {

    const PEPPER: &str = "PkCt&farjdWL2&WTaoddA2u7S4hfxDkbtNFxxU92";

    // Clone the password into bytes to be concatenated with the pepper
    let mut extended_password: String = password
        .clone()
        .as_bytes()
        .iter()
        .map(|x| x.to_string())
        .collect();

    // Connect the password with the pepper 
    extended_password.extend(PEPPER.as_bytes().iter().map(|x| x.to_string()));

    // Convert extended password to bytes and begin hashing with salt
    let hash = hash_with_salt(extended_password.as_bytes(), DEFAULT_COST, generate_salt()).unwrap();

    // Confirm hash
    // match self.compare_password(password, hash)

    hash.to_string()
}


/// Verify Password by taking in a single parameter being that of password 
/// - passowrd : &str
fn verify_password(password: &str) -> Password_Object {

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
fn verify_username(username: &str) -> bool {
    
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
fn regex_pattern_match(username: &str) -> bool {
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
fn censor_username(username: &str) -> bool {

    // impl rate limit
    // (burst, rate, seconds)
    // let ratelimiter = Ratelimiter::new(1, 1, 1); //  1/s with no burst

    if username.is_inappropriate() {
        println!("Username {} | is inappropriate", username);
        return false
    }

    username.is_inappropriate()
}
