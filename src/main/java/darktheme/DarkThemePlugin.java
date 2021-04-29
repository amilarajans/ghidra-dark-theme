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

import java.awt.Window;

import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import com.formdev.flatlaf.FlatDarculaLaf;
import com.formdev.flatlaf.FlatLaf;

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

    // setting names
    private final static String DARK_THEME = "Dark theme";
    private final static String OPTIONS_TITLE = "Theme";
    private final static String MENU_BAR_EMBEDDED = "Menu Bar Embedded";
    private final static String UNIFIED_TITLE_BAR = "Unified Title Bar";

    // preference names
    private final static String IS_DARK_THEME_ENABLED = "IsDarkThemeEnabled";
    private final static String IS_MENU_BAR_EMBEDDED_ENABLED = "IsMenuBarEmbeddedEnabled";
    private final static String IS_UNIFIED_TITLE_BAR_ENABLED = "IsUnifiedTitleBarEnabled";

    private boolean issuedLafNotification;

    private boolean isDarkThemeEnabled;
    private boolean isMenuBarEmbeddedEnabled;
    private boolean isUnifiedTitleBarEnabled;

    public DarkThemePlugin(PluginTool tool) {
        super(tool);

        SystemUtilities.assertTrue(tool instanceof FrontEndTool, "Plugin added to the wrong type of tool");
        initLookAndFeelOptions();
    }

    private static boolean isDisplayableFrameOrDialog(Window w) {
        return w.isDisplayable() && (w instanceof JFrame || w instanceof JDialog);
    }

    private void initLookAndFeelOptions() {

        ToolOptions opt = tool.getOptions(OPTIONS_TITLE);

        isDarkThemeEnabled = Boolean.parseBoolean(Preferences.getProperty(IS_DARK_THEME_ENABLED, Boolean.FALSE.toString()));
        opt.registerOption(DARK_THEME, OptionType.BOOLEAN_TYPE, isDarkThemeEnabled,
                new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Dark_theme"),
                "Set the dark theme for Ghidra");
        isDarkThemeEnabled = opt.getBoolean(DARK_THEME, isDarkThemeEnabled);

        isUnifiedTitleBarEnabled = Boolean.parseBoolean(Preferences.getProperty(IS_UNIFIED_TITLE_BAR_ENABLED, Boolean.FALSE.toString()));
        opt.registerOption(UNIFIED_TITLE_BAR, OptionType.BOOLEAN_TYPE, isUnifiedTitleBarEnabled,
                new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Unified_Background"),
                "Set the unified title bar for Ghidra. (Enable Dark theme)");

        isUnifiedTitleBarEnabled = opt.getBoolean(UNIFIED_TITLE_BAR, isUnifiedTitleBarEnabled);

        isMenuBarEmbeddedEnabled = Boolean.parseBoolean(Preferences.getProperty(IS_MENU_BAR_EMBEDDED_ENABLED, Boolean.FALSE.toString()));
        opt.registerOption(MENU_BAR_EMBEDDED, OptionType.BOOLEAN_TYPE, isMenuBarEmbeddedEnabled,
                new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, "Menu_Bar_Embedded"),
                "Embed the menu bar in title bar for Ghidra. (Enable Dark theme)");

        isMenuBarEmbeddedEnabled = opt.getBoolean(MENU_BAR_EMBEDDED, isMenuBarEmbeddedEnabled);

        opt.addOptionsChangeListener(this);
    }

    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue, Object newValue) {
        // since all the values are booleans (for now)
        boolean newBooleanValue = Boolean.parseBoolean(newValue.toString());
        String value = Boolean.toString(newBooleanValue);
        if (optionName.equals(DARK_THEME)) {
            if (newBooleanValue) {
                issueLaFNotification();
            }
            Preferences.setProperty(IS_DARK_THEME_ENABLED, value);
            Preferences.store();
        }

        if (optionName.equals(UNIFIED_TITLE_BAR)) {
            if (newBooleanValue) {
                issueLaFNotification();
            }
            Preferences.setProperty(IS_UNIFIED_TITLE_BAR_ENABLED, value);
            Preferences.store();
        }

        if (optionName.equals(MENU_BAR_EMBEDDED)) {
            if (newBooleanValue) {
                issueLaFNotification();
            }
            Preferences.setProperty(IS_MENU_BAR_EMBEDDED_ENABLED, value);
            Preferences.store();
        }
    }

    private void issueLaFNotification() {
        if (issuedLafNotification) {
            return;
        }

        issuedLafNotification = true;
        Msg.showInfo(getClass(), null, "Settings changed",
                "The new changes will take effect \nafter you exit and restart Ghidra.");
    }

    @Override
    protected void init() {
        super.init();
        if (isDarkThemeEnabled) {
            FlatDarculaLaf.install();
            updateUI();
        }

        // set the window decoration mode
        FlatLaf.setUseNativeWindowDecorations(isUnifiedTitleBarEnabled || isMenuBarEmbeddedEnabled);

        updateEmbeddedMenuBar();

        updateTitleBar();
    }

    private void updateTitleBar() {
        UIManager.put("TitlePane.unifiedBackground", isUnifiedTitleBarEnabled);
        SystemUtilities.runSwingLater(FlatLaf::repaintAllFramesAndDialogs);
    }

    private void updateEmbeddedMenuBar() {
        UIManager.put("TitlePane.menuBarEmbedded", isMenuBarEmbeddedEnabled);
        SystemUtilities.runSwingLater(FlatLaf::revalidateAndRepaintAllFramesAndDialogs);
    }

    private void updateUI() {
        SystemUtilities.runSwingLater(() -> {
            // iterate through all the windows
            for (Window w : Window.getWindows()) {
                if (isDisplayableFrameOrDialog(w)) {
                    // update UI components
                    SwingUtilities.updateComponentTreeUI(w);
                }
            }
        });
    }

    @Override
    public void dispose() {
        ToolOptions opt = tool.getOptions(OPTIONS_TITLE);
        opt.removeOptionsChangeListener(this);
        super.dispose();
    }
}
