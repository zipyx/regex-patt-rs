mod security;

use rustrict::CensorStr;
use ratelimit::*;
use clocksource::{DateTime, SecondsFormat};

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
    let password = "$2y$12$C4st7WVSU6nPOTip/leWP.qcPCAOoiIKHEJ5.SbkrCVJ0dlbuwGxm";

    let _censored: String = "Hello, f4gg0t!!!".censor();
    let _inappropriate: bool = "fAcKing".is_inappropriate();

    // println!("Censored: {} -> {}", censored, test_one);
    // println!("Inappropriate: {} -> {}", inappropriate, test_two);

    
}
