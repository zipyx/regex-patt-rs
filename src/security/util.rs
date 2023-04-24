use std::{fs::File, io::{BufReader, BufRead}, collections::HashSet};

pub fn read_file(file_name: &str) -> Vec<String> {

    let mut list = Vec::new();
    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    for line in reader.lines() {
        list.push(line.unwrap());
    }
    list
}


pub fn read_file_hashset(file_name: &str) -> HashSet<String> {

    let file = File::open(file_name).unwrap();
    let reader = BufReader::new(file);
    let list: HashSet<String> = reader.lines().map(|line| line.unwrap()).collect();
    return list
}

