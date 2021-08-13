/* ###
 * IP: GHIDRA
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
package ghidra.app.plugin.core.decompile.actions;

import docking.action.MenuData;
import ghidra.app.plugin.core.decompile.DecompilePlugin;
import ghidra.app.util.HelpTopics;
import ghidra.pcode.floatformat.BigFloat;
import ghidra.pcode.floatformat.FloatFormat;
import ghidra.pcode.floatformat.FloatFormatFactory;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.HelpLocation;

import java.math.BigDecimal;
import java.math.BigInteger;

/**
 * Convert a selected constant in the decompiler window to a character representation.
 */
public class ConvertDoubleAction extends ConvertConstantAction {

	public ConvertDoubleAction(DecompilePlugin plugin) {
		super(plugin, "Convert To Double", EquateSymbol.FORMAT_DOUBLE);
		setHelpLocation(new HelpLocation(HelpTopics.DECOMPILER, "ActionConvert"));
		setPopupMenuData(new MenuData(new String[] { "Double" }, "Decompile"));
	}

	@Override
	public String getMenuPrefix() {
		return "Double: ";
	}

	@Override
	public String getMenuDisplay(long value, int size, boolean isSigned) {
		BigDecimal bigDouble = getDouble(value);
		if (bigDouble == null) {
			return "Nan";
		}
		String DoubleFormat = bigDouble.toString();
		return DoubleFormat;
	}

	@Override
	public String getEquateName(long value, int size, boolean isSigned, Program program) {
		BigDecimal bigDouble = getDouble(value);
		if (bigDouble == null) {
			return null;
		}
		String DoubleFormat = bigDouble.toString();
		return DoubleFormat;
	}

	public BigDecimal getDouble(long value) {
		int FloatSize = 8;				//size for Double type
		FloatFormat format = FloatFormatFactory.getFloatFormat(FloatSize);

		BigFloat bigDouble =  format.getHostFloat(BigInteger.valueOf(value));
		BigDecimal bigDecimal = format.round(bigDouble);
		return bigDecimal;
	}
}
