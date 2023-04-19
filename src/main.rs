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
    let re = Regex::new(r"^[a-zA-Z0-9_]+$").unwrap();

    if re.is_match(normalized.to_string().as_str()) {
        println!("Username is valid {} == {}", 
            username, 
            normalized
        );
        return true
    } else {
        println!("Username is invalid {}", username);
        return false
    }
}

fn read_file(file_name: &str) -> Vec<String> {

    let mut passwords = Vec::new();
    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        passwords.push(line.unwrap());
    }
    passwords
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

    // check weak passwords
    let weak_passwords = read_file("weakpasswords.txt");
    for pass in weak_passwords {
        verify_password(pass.as_str());
    }

    // check breached passwords
    let breached_passwords = read_file("breachedpasswords.txt");
    for pass in breached_passwords {
        verify_password(pass.as_str());
    }
    
}
