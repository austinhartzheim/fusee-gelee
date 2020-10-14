use clap::{crate_version, App, Arg};
use std::fs::File;

use fusee::{ExploitDriver, LinuxBackend};

fn main() {
    let args = App::new("fusee")
        .version(crate_version!())
        .arg(
            Arg::with_name("payload")
                .required(true)
                .takes_value(true)
                .help("Path to ARM payload to launch"),
        )
        .arg(
            Arg::with_name("vendor-id")
                .short("V")
                .default_value("0955")
                .help("Vendor ID, hexadecimal encoded"),
        )
        .arg(
            Arg::with_name("product-id")
                .short("P")
                .default_value("7321")
                .help("Product ID, hexadecimal encoded"),
        )
        .get_matches();

    let vendor_id = u16::from_str_radix(
        args.value_of("vendor-id").expect("Vendor ID not provided"),
        16,
    )
    .expect("Vendor ID must be a 16-bit hexadecimal integer.");
    let product_id = u16::from_str_radix(
        args.value_of("product-id")
            .expect("Product ID not provided"),
        16,
    )
    .expect("Product ID must be a 16-bit hexadecimal integer.");

    let mut driver: ExploitDriver<LinuxBackend> =
        ExploitDriver::discover(vendor_id, product_id).expect("Failed to find USB device");

    let target_payload = File::open(args.value_of("payload").expect("Payload path not provided"))
        .expect("Failed to open payload file");
    driver
        .exploit(target_payload, &fusee::payload::INTERMEZZO_DEFAULT[..])
        .expect("Failed to execute exploit");
}
