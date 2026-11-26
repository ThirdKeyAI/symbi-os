-- Symbiont defaults for the pinned Hyprland Lua configuration API.
local config_home = os.getenv("XDG_CONFIG_HOME") or (assert(os.getenv("HOME")) .. "/.config")
local config_dir = config_home .. "/hypr/"
dofile(config_dir .. "input.lua")
dofile(config_dir .. "appearance.lua")
dofile(config_dir .. "bindings.lua")

hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })
hl.on("hyprland.start", function()
    hl.exec_cmd("/usr/bin/waybar")
end)
