#![feature(test)]
extern crate test;

extern crate jail;

use jail::process::Jailed;
use jail::{RunningJail, StoppedJail};
use std::process::Command;
use test::Bencher;

#[bench]
fn start_stop_jail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue").start().unwrap();
        running.kill().unwrap();
    });
}

#[bench]
fn start_stop_ipv4jail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue")
            .ip("127.0.1.1".parse().unwrap())
            .start()
            .unwrap();
        running.kill().unwrap();
    })
}

#[bench]
fn start_stop_ipv6jail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue")
            .ip("fe80::2".parse().unwrap())
            .start()
            .unwrap();
        running.kill().unwrap();
    })
}

#[bench]
fn start_stop_ipjail(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue")
            .ip("127.0.1.1".parse().unwrap())
            .ip("fe80::2".parse().unwrap())
            .start()
            .unwrap();
        running.kill().unwrap();
    })
}

#[bench]
fn start_echo_helloworld_stop(b: &mut Bencher) {
    b.iter(|| {
        let running = StoppedJail::new("/rescue").start().unwrap();

        Command::new("/echo")
            .arg("hello world")
            .jail(&running)
            .output()
            .unwrap();

        running.kill().unwrap();
    });
}

#[bench]
fn echo_helloworld_jailed(b: &mut Bencher) {
    let running = StoppedJail::new("/rescue").start().unwrap();
    b.iter(|| {
        Command::new("/echo")
            .arg("hello world")
            .jail(&running)
            .output()
            .unwrap();
    });
    running.kill().unwrap();
}

#[bench]
fn echo_helloworld_free(b: &mut Bencher) {
    b.iter(|| {
        Command::new("/rescue/echo")
            .arg("hello world")
            .output()
            .unwrap();
    });
}

#[bench]
fn get_ips(b: &mut Bencher) {
    let running = StoppedJail::new("/rescue")
        .ip("127.0.1.1".parse().unwrap())
        .ip("fe80::2".parse().unwrap())
        .start()
        .unwrap();
    b.iter(|| running.ips().unwrap());
    running.kill().unwrap();
}

#[bench]
fn get_params(b: &mut Bencher) {
    let running = StoppedJail::new("/rescue").start().unwrap();
    b.iter(|| running.params().unwrap());
    running.kill().unwrap();
}

#[bench]
fn save(b: &mut Bencher) {
    let running = StoppedJail::new("/rescue").start().unwrap();
    b.iter(|| running.save().unwrap());
    running.kill().unwrap();
}

#[bench]
fn iterate_100_jails(b: &mut Bencher) {
    // create 100 jails to iterate over
    let mut running_jails: Vec<RunningJail> = (1..100)
        .map(|i| {
            StoppedJail::new("/rescue")
                .name(format!("benchjail_iterate_{}", i))
                .start()
                .expect("failed to start jail")
        })
        .collect();

    b.iter(|| {
        for running in RunningJail::all() {
            println!("jail: {}", running.name().unwrap());
        }
    });

    // kill all the jails again
    for to_kill in running_jails.drain(..) {
        to_kill.kill().expect("failed to kill jail");
    }
}
