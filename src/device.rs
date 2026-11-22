use std::collections::VecDeque;

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

pub struct MemoryDevice {
    pub received: VecDeque<Vec<u8>>,
    pub transmitted: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl MemoryDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            received: VecDeque::new(),
            transmitted: VecDeque::new(),
            mtu,
        }
    }
}

impl Device for MemoryDevice {
    type RxToken<'a> = ReceiveToken;
    type TxToken<'a> = TransmitToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }

    fn receive(&mut self, _: Instant) -> Option<(ReceiveToken, TransmitToken<'_>)> {
        self.received.pop_front().map(|packet| {
            let transmit = TransmitToken {
                queue: &mut self.transmitted,
            };
            (ReceiveToken { packet }, transmit)
        })
    }

    fn transmit(&mut self, _: Instant) -> Option<TransmitToken<'_>> {
        Some(TransmitToken {
            queue: &mut self.transmitted,
        })
    }
}

pub struct ReceiveToken {
    packet: Vec<u8>,
}

impl phy::RxToken for ReceiveToken {
    fn consume<R, F>(self, function: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        function(&self.packet)
    }
}

pub struct TransmitToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl phy::TxToken for TransmitToken<'_> {
    fn consume<R, F>(self, length: usize, function: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; length];
        let result = function(&mut packet);
        self.queue.push_back(packet);
        result
    }
}
