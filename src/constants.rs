// Exploit specifics
pub const COPY_BUFFER_ADDRESSES: [usize; 2] = [0x40005000, 0x40009000];
pub const STACK_END: usize = 0x40010000;
pub const STACK_SPRAY_START: usize = 0x40014E40;
pub const STACK_SPRAY_END: usize = 0x40017000;
pub const PAYLOAD_START_ADDR: usize = 0x40010E40;
pub const RCM_PAYLOAD_ADDR: usize = 0x40010000;
