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
package ghidra.framework;

import generic.jar.ResourceFile;
import ghidra.util.SystemUtilities;
import ghidra.util.config.NestedProperties;
import utility.application.ApplicationLayout;

import java.awt.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;

import static ghidra.util.config.ColorHexConvert.toColorFromString;


public class ColorProperties extends NestedProperties {

    /**
     * The name of the Color properties file.
     */
    public static final String COLOR_PROPERTY_NAME = "Color.properties";
    public static final String COLOR_PROPERTY_FILE = "/RuntimeScripts/Common/support/Color.properties";
    public static final String COLOR_PROPERTY_FILE_SUB = "/support/Color.properties";

    /**
     * Creates a new color properties from the given config properties file.
     *
     * @param colorPropertiesFile The color properties file.
     * @throws IOException If there was a problem loading/reading a discovered properties file.
     */
    public ColorProperties(ResourceFile colorPropertiesFile) throws IOException {

        if (!colorPropertiesFile.exists()) {
            throw new FileNotFoundException(
                    COLOR_PROPERTY_NAME + " file does not exist: " + colorPropertiesFile);
        }
        try (InputStream in = colorPropertiesFile.getInputStream()) {
            load(in);
        }
    }

    /**
     * Creates a new color properties from the color properties files found
     * in the given application root directories.  If multiple color properties files
     * are found, the properties from the files will be combined.  If duplicate keys exist,
     * the newest key encountered will overwrite the existing key.
     *
     * @param applicationRootDirs The application root directories to look for the properties files in.
     * @throws IOException If there was a problem loading/reading a discovered properties file.
     */
    public ColorProperties(Collection<ResourceFile> applicationRootDirs) throws IOException {
        // Application installation directory
        ResourceFile applicationInstallationDir = applicationRootDirs.iterator().next().getParentFile();
        if (SystemUtilities.isInDevelopmentMode()) {
            for (ResourceFile appRoot : applicationRootDirs) {
                ResourceFile colorPropertiesFile = new ResourceFile(appRoot, COLOR_PROPERTY_FILE);
                if (colorPropertiesFile.exists()) {
                    try (InputStream in = colorPropertiesFile.getInputStream()) {
                        load(in);
                    }
                }
            }
        }
        else {
            ResourceFile colorPropertiesFile = new ResourceFile(applicationInstallationDir, COLOR_PROPERTY_FILE_SUB);
            if (colorPropertiesFile.exists()) {
                try (InputStream in = colorPropertiesFile.getInputStream()) {
                    load(in);
                }
            }
        }
    }

    /**
     * Get Properties from Color.properties by key
     *
     * @param key Color.properties key
     * @return Color Object
     * */
	public Color readColor(String key) {
		Color color = toColorFromString(getProperty(key));
		return color;
	}

    /**
     * Get Properties from ApplicationLayout.getColorProperties() by key
     *
     * @param key Color.properties key
     * @return Color Object
     * */
    public static Color findColor(String key){
        Color color = ApplicationLayout.getColorProperties().readColor(key);
        return color;
    }

}
