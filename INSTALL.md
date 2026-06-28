# Installing PlayerSync (Soli's Version)

## 1. Disable the main PlayerSync plugin

If you have the official Mare Synchronos / PlayerSync installed, disable it first.

- Open `/xlplugins` in-game
- Find **PlayerSync** in the Installed Plugins list
- Toggle it off 

You cannot run both versions at the same time.

## 2. Add the custom plugin repository

- Open `/xlplugins` → **Settings** → **Experimental**
- Under **Custom Plugin Repositories**, paste this URL and click the **+** button:
  ```
  https://raw.githubusercontent.com/solona-m/plugins/main/repo.json
  ```
- Click **Save**

## 3. Install Soli's Version

- Go to the **All Plugins** tab in `/xlplugins`
- Search for **PlayerSync (Soli's Version)**
- Click **Install**
- Enable the plugin 

## 4. Viewing logs

If something isn't working, open the Dalamud log:

- Run `/xllog` in-game
- In the log window, click the magnifiying glass. filter by source: type `MareSempiterne` in the filter box. click the plus sign
- Set the level filter to **Warning**
- Two of the crash fixes are silent, but the most common one will print this to the log, if you're curious: | WRN | [MareSempiterne] [Animat...dGuard]{3} AnimationBindGuard: skipped a null skeleton-mapper bind that would have crashed Havok (total caught: 1).

Share any relevant log lines when reporting issues. you can right click the copy button at top to get the whole log

## 5. Crash reports

If the game crashes, you may see a dialog with an option to restart and a button to save troubleshooting information. Click this. It generates a crash pack (a `.tspack` file), please send it to **solona** on Discord.
