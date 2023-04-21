use std::{fs::File, io::{BufReader, BufRead}};

use regex::Regex;
use unicode_normalization::{IsNormalized, UnicodeNormalization};
use ratelimit::*;

/// Verify passwords
fn verify_password(password: &str) -> bool {

    // check password length
    let check_password_length = password.len() >= 8 && password.len() <= 64;
    print!("Password | {} == length | {} \n", password, check_password_length);
    check_password_length
}

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

fn read_file(file_name: &str) -> Vec<String> {

    let mut list = Vec::new();
    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        list.push(line.unwrap());
    }
    list
}

fn main() {

    // create a list of usernames
    let _usernames = vec![
        "test",
        "ℌ",
        "ℍ",
        "ÅEΩLI",
        "007",
        "Äffin",
        "Äffinjsafdsajfsajf",
    ].iter().map(|&s| s.to_string()).collect::<Vec<String>>();

    // verify usernames
    let usernames = vec![
        "4ss",
        "d1ck",
        "f4gg0t",
        "B00bs",
        "b00bs",
        "test",
        "ℌ",
        "ℍ",
        "ÅEΩLI",
        "007",
        "Äffin",
        "Äffinjsafdsajfsajf",
    ].iter().map(|&s| verify_username(s)).collect::<Vec<bool>>();

    // verify_username(test);

    // check weak passwords
    let weak_passwords = read_file("weakpasswords.txt");
    for pass in weak_passwords {
        verify_username(pass.as_str());
    }

    // check breached passwords
    let breached_passwords = read_file("breachedpasswords.txt");
    for pass in breached_passwords {
        // verify_password(pass.as_str());
    }
    
}
