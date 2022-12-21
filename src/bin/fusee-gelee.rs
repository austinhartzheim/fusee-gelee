use clap::{crate_version, Arg, Command};
use std::fs::File;

use fusee::{ExploitDriver, LinuxBackend};

fn main() {
    let args = Command::new("fusee")
        .version(crate_version!())
        .arg(
            Arg::new("payload")
                .required(true)
                .help("Path to ARM payload to launch"),
        )
        .arg(
            Arg::new("vendor-id")
                .short('v')
                .default_value("0955")
                .help("Vendor ID, hexadecimal encoded"),
        )
        .arg(
            Arg::new("product-id")
                .short('p')
                .default_value("7321")
                .help("Product ID, hexadecimal encoded"),
        )
        .get_matches();

    let vendor_id = u16::from_str_radix(
        args.get_one::<String>("vendor-id")
            .expect("Vendor ID not provided"),
        16,
    )
    .expect("Vendor ID must be a 16-bit hexadecimal integer.");
    let product_id = u16::from_str_radix(
        args.get_one::<String>("product-id")
            .expect("Product ID not provided"),
        16,
    )
    .expect("Product ID must be a 16-bit hexadecimal integer.");

    let mut driver: ExploitDriver<LinuxBackend> =
        ExploitDriver::discover(vendor_id, product_id).expect("Failed to find USB device");

    let target_payload = File::open(
        args.get_one::<String>("payload")
            .expect("Payload path not provided"),
    )
    .expect("Failed to open payload file");
    driver
        .exploit(target_payload, &fusee::payload::INTERMEZZO_DEFAULT[..])
        .expect("Failed to execute exploit");
}
