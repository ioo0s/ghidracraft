/* ###
 * IP: BinCraft
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

use cxx::{type_id, ExternType};
use std::io::Read;
use std::pin::Pin;
use pcodecraft::{Address, Varnode};

use crate::patch::Patches;

#[cfg(debug_assertions)]
pub mod debug;
pub mod release;

pub mod ffi {
    pub use super::release::*;
    #[cfg(debug_assertions)]
    pub use super::debug::*;
}

impl Address for ffi::Address {
    fn space(&self) -> String {
        unsafe {
            self.getSpace().as_ref().unwrap().getName().to_string()
        }
    }

    fn offset(&self) -> u64 {
        self.getOffset() as u64
    }

    fn debug_print(&self) -> String {
        format!("address({}, 0x{:x})", self.space(), self.offset())
    }
}

impl std::fmt::Debug for ffi::Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.debug_print())
    }
}

struct RustReader<'a> {
    reader: Pin<&'a mut ffi::StreamReader>,
}

impl<'a> RustReader<'a> {
    pub fn new(reader: Pin<&'a mut ffi::StreamReader>) -> Self {
        Self { reader }
    }
}

impl<'a> Read for RustReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        Ok(self.reader.as_mut().read(buf))
    }
}

unsafe fn new_patches(arch: *mut ffi::Architecture) -> Box<Patches> {
    Box::new(Patches::new(arch))
}
