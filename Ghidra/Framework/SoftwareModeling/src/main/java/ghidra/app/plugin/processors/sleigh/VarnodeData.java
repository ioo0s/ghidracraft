/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
/*
 * Created on Feb 4, 2005
 *
 */
package ghidra.app.plugin.processors.sleigh;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.pcode.Varnode;

/**
 * 
 *
 *  All the resolved pieces of data needed to build a Varnode
 */
public class VarnodeData {
	public AddressSpace space;
	public long offset;
	public int size;

	public VarnodeData() {
	}

	public VarnodeData(AddressSpace space, long offset, int size) {
		this.space = space;
		this.offset = offset;
		this.size = size;
	}

	public static VarnodeData of(Varnode varnode) {
		if (varnode == null) {
			return null;
		}

		Address addr = varnode.getAddress();
		VarnodeData data = new VarnodeData(
			addr.getAddressSpace(),
			addr.getOffset(),
			varnode.getSize()
		);
		return data;
	}
}
