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

use crate::patch::Patches;

unsafe impl ExternType for ffi::OpCode {
    type Id = type_id!("OpCode");
    type Kind = cxx::kind::Trivial;
}

// UGLY ALERT! These complex duplication is due to the lack of supporting
// debug asserton (check for debug build) in #[cxx::bridge].
// This should be resolved once cxx bridge support such conditional compilation.
#[cfg(debug_assertions)]
pub mod debug;

#[cfg(debug_assertions)]
pub use self::debug as ffi;

#[cfg(not(debug_assertions))]
pub mod release;

#[cfg(not(debug_assertions))]
pub use self::release as ffi;

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
