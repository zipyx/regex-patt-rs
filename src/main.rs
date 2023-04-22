use std::{fs::File, io::{BufReader, BufRead}, collections::HashSet};

use rustrict::{CensorStr, CensorIter};
use regex::Regex;
use unicode_normalization::{IsNormalized, UnicodeNormalization};
use ratelimit::*;
use clocksource::{DateTime, SecondsFormat};

struct password_obj {
    username: String,
    validity: bool,
    message: String,
}


/// Verify passwords
fn verify_password(password: &str) -> password_obj {

    // Check instantiate

    // check password length
    let check_password_length = password.len() >= 8 && password.len() <= 64;

    let weak_passwords = read_file_hashset("weakpasswords.txt");
    let breached_passwords = read_file_hashset("breachedpasswords.txt");

    // if 1st rule is met, check for second rule and return true if both are met
    // if check_password_length && weak_passwords.contains(password) {
    //     println!("Password {} with length {} is weak", password, check_password_length);
    //     return false
    // }

    // check password 
    if check_password_length {
        if breached_passwords.contains(password) ||
        weak_passwords.contains(password) {
            return password_obj {
                username: password.to_string(),
                validity: true,
                message: "found in blacklist".to_string(),
            }

        } else {
            return password_obj {
                username: password.to_string(),
                validity: false,
                message: "not found in blacklist".to_string(),
            }
        }

    } else {
        return password_obj {
            username: password.to_string(),
            validity: false,
            message: "password length is not met".to_string(),
        }
    }
    // if check_password_length && (breached_passwords.contains(password) ||
    // weak_passwords.contains(password))
    // {
    //     return password_obj {
    //         username: password.to_string(),
    //         validity: true,
    //     }
    // } else {
    //     password_obj {
    //         username: password.to_string(),
    //         validity: false,
    //     }
    // }

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

fn read_file(file_name: &str) -> Vec<String> {

    let mut list = Vec::new();
    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        list.push(line.unwrap());
    }
    list
}


fn read_file_hashset(file_name: &str) -> HashSet<String> {

    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    let list: HashSet<String> = reader.lines().map(|line| line.unwrap()).collect();
    return list
}

fn main() {

    let _test_one = "Hello, f4gg0t!!!";
    let _test_two = "fAcKing";
    let _censored: String = "Hello, f4gg0t!!!".censor();
    let _inappropriate: bool = "fAcKing".is_inappropriate();

    // println!("Censored: {} -> {}", censored, test_one);
    // println!("Inappropriate: {} -> {}", inappropriate, test_two);

    // verify usernames
    // let _usernames = vec![
    //     "4ss",
    //     "d1ck",
    //     "f4gg0t",
    //     "B00bs",
    //     "b00bs",
    //     "test",
    //     "ℌ",
    //     "ℍ",
    //     "ÅEΩLI",
    //     "007",
    //     "Äffin",
    //     "Äffinjsafdsajfsajf",
    // ].iter().map(|&s| verify_username(s)).collect::<Vec<bool>>();


    println!("====================");

    // check weak passwords
    // let weak_passwords = read_file_hashset("weakpasswords.txt");
    // for pass in weak_passwords.clone() {
    //     verify_password(pass.as_str());
    // }
    println!("====================");

    // Censorship
    // for pass in weak_passwords {
    //     censor_username(pass.as_str());
    // }

    println!("====================");

    // check breached passwords
    // verify_password("1password");
    // let breached_passwords = read_file("breachedpasswords.txt");
    // for pass in breached_passwords.clone() {
    //     verify_password(pass.as_str());
    // }

    println!("====================");

    // censorship breached passwords
    // for pass in breached_passwords {
    //     censor_username(pass.as_str());
    // }
    println!("====================");

    // generate 30 passwords in a list 
    let passwords = vec![
        "hello",
        "hellomate",
        "1password",
        "password",
        "something7",
        "something8",
        "piasco2986",
        "commonpascoltwentyseven",
        "commonpascoltwentyeight",
        "eleven88alk",
        "pacifico",
        "liverpool",
        "pacifico99",
        "pacifico100",
        "football",
        "bubbles",
        "matthew1",
        "marie1",
        "loveme1",
        "joshua1",
        "iloveyou3",
        "hollister1",
        "hello1",
        "hmm",
    ];

    // passwords.iter().map(|&s| verify_password(s)).collect::<Vec<bool>>();

    for line in passwords {
        let passkey = verify_password(line);
        match passkey.validity {
            true => println!("{} {}", passkey.username, passkey.message),
            false => println!("{} {}", passkey.username, passkey.message),
        }
    }

    // (burst capacity, quantum, rate)
    // creating a new token bucket `RateLimiter` which can hold up to `capacity tokens`,
    // `quantum` tokens will be added to the bucket at 
    // `rate` times per second. The token bucket intially starts without 
    // any tokens, this ensures the rate does not start high initially
    // let limiter = Ratelimiter::new(3, 1, 3); // 3 connections max burst if suddenly 2 people connect at once, at 100/s (per second)

    // for i in 0..10 {
    //     limiter.wait();
    //     println!(
    //         "{}: T -{}",
    //         DateTime::now().to_rfc3339_opts(SecondsFormat::Millis, false),
    //         10 - i
    //     );
    // }

    // limiter.wait();

    // println!("Ignition");
    
}
