mod security;

use rustrict::CensorStr;
use ratelimit::*;
use clocksource::{DateTime, SecondsFormat};

use crate::security::auth::Password_Object;

/// Check timer for rate limiter
fn rate_limiter() {

    // (burst capacity, quantum, rate)
    // creating a new token bucket `RateLimiter` which can hold up to `capacity tokens`,
    // `quantum` tokens will be added to the bucket at 
    // `rate` times per second. The token bucket intially starts without 
    // any tokens, this ensures the rate does not start high initially
    let limiter = Ratelimiter::new(3, 1, 3); // 3 connections max burst if suddenly 2 people connect at once, at 100/s (per second)

    for i in 0..10 {
        limiter.wait();
        println!(
            "{}: T -{}",
            DateTime::now().to_rfc3339_opts(SecondsFormat::Millis, false),
            10 - i
        );
    }

    limiter.wait();
    println!("Ignition");

}

/// Verify passwords
fn main() {

    let username = "something";
    let password = "something";

    let x = security::auth::hash_password(password.to_string());
    let generated_password = security::auth::generate_password(password.to_string());
    let username_response: bool = security::auth::verify_username(username);
    let password_response: bool = security::auth::compare_password(generated_password, x.clone());


    println!("#################################################################");
    println!("Username: {} validation result -> {}", username, username_response);
    println!("#################################################################");
    println!("Hash Password: {}", x.clone());
    println!("#################################################################");
    println!("Password: {} validation result -> {}", password, password_response);
    
}
