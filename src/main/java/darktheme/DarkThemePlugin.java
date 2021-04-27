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
package darktheme;

import static ghidra.docking.util.DockingWindowsLookAndFeelUtils.LAST_LOOK_AND_FEEL_KEY;
import static ghidra.docking.util.DockingWindowsLookAndFeelUtils.getInstalledLookAndFeelName;
import static ghidra.docking.util.DockingWindowsLookAndFeelUtils.getLookAndFeelNames;

import java.util.List;

import javax.swing.UIManager;

import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.intellijthemes.FlatDraculaIJTheme;

import docking.options.editor.StringWithChoicesEditor;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.main.FrontEndTool;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = DarkThemePluginPackage.NAME,
	category = PluginCategoryNames.SUPPORT,
	shortDescription = "Dark theme",
	description = "This plugin provides Dark theme to Ghidra"
)
//@formatter:on
public class DarkThemePlugin extends Plugin implements FrontEndOnly, OptionsChangeListener {

	private String selectedLookAndFeel;
	public final static String LOOK_AND_FEEL_NAME = "Swing Look And Feel";
	private final static String OPTIONS_TITLE = ToolConstants.TOOL_OPTIONS;
	private final static String DARK = "Dark";
	private final static String DARK_LAF = "com.formdev.flatlaf.FlatDarculaLaf";

	private static boolean issuedLafNotification;

	public DarkThemePlugin(PluginTool tool) {
		super(tool);

		SystemUtilities.assertTrue(tool instanceof FrontEndTool, "Plugin added to the wrong type of tool");
		initLookAndFeelOptions();
	}

	private void initLookAndFeelOptions() {

		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

		selectedLookAndFeel = getInstalledLookAndFeelName();
		List<String> lookAndFeelNames = getLookAndFeelNames();
		lookAndFeelNames.add(DARK);
		opt.registerOption(LOOK_AND_FEEL_NAME, OptionType.STRING_TYPE, selectedLookAndFeel,
				new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Look_And_Feel"),
				"Set the look and feel for Ghidra.  After you change the "
						+ "look and feel, you will have to restart Ghidra to see the effect.",
				new StringWithChoicesEditor(lookAndFeelNames));
		selectedLookAndFeel = opt.getString(LOOK_AND_FEEL_NAME, selectedLookAndFeel);

		opt.addOptionsChangeListener(this);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {

		if (optionName.equals(LOOK_AND_FEEL_NAME)) {
			String newLookAndFeel = (String) newValue;
			if (!newLookAndFeel.equals(selectedLookAndFeel)) {
				issueLaFNotification();
			}

			saveLookAndFeel((String) newValue);
		}
	}

	private void saveLookAndFeel(String lookAndFeelName) {
		selectedLookAndFeel = lookAndFeelName;
		Preferences.setProperty(LAST_LOOK_AND_FEEL_KEY, selectedLookAndFeel);
		Preferences.store();
	}

	private void issueLaFNotification() {
		if (issuedLafNotification) {
			return;
		}

		issuedLafNotification = true;
		Msg.showInfo(getClass(), null, "Look And Feel Updated",
				"The new Look and Feel will take effect \nafter you exit and restart Ghidra.");
	}

	@Override
	protected void init() {
		super.init();
		if (Preferences.getProperty(LAST_LOOK_AND_FEEL_KEY).equals(DARK)) {
			try {
				FlatLightLaf.install();
				FlatDraculaIJTheme.install();
				UIManager.setLookAndFeel(DARK_LAF);
			} catch (Exception exc) {
				Msg.error(DarkThemePlugin.class, "Error loading Look and Feel: " + exc, exc);
			}
		}
	}

	@Override
	public void dispose() {
		ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
		opt.removeOptionsChangeListener(this);
		super.dispose();
	}
}
