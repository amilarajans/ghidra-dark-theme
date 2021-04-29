package darktheme;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class DarkThemePluginPackage extends PluginPackage {
	public static final String NAME = "DarkTheme";

	public DarkThemePluginPackage() {
		super(NAME, ResourceManager.loadImage("images/dracula.svg"), "Dark theme plugin", CORE_PRIORITY);
	}
}
