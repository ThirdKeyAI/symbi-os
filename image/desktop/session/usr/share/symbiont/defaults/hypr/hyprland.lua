-- Symbiont defaults for the pinned Hyprland Lua configuration API.
local config_home = os.getenv("XDG_CONFIG_HOME") or (assert(os.getenv("HOME")) .. "/.config")
local config_dir = config_home .. "/hypr/"
dofile(config_dir .. "input.lua")
dofile(config_dir .. "appearance.lua")

hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })
hl.on("hyprland.start", function()
    hl.exec_cmd("/usr/libexec/symbi-launch-desktop-services")
end)

hl.bind("SUPER + ALT + SPACE", hl.dsp.exec_cmd("/usr/bin/walker"))
hl.bind("SUPER + Return", hl.dsp.exec_cmd("/usr/bin/foot"))
hl.bind("SUPER + Q", hl.dsp.window.close())
hl.bind("SUPER + F", hl.dsp.window.fullscreen({ mode = "fullscreen", action = "toggle" }))
for workspace = 1, 4 do
    hl.bind("SUPER + " .. workspace, hl.dsp.focus({ workspace = workspace }))
    hl.bind("SUPER + SHIFT + " .. workspace, hl.dsp.window.move({ workspace = workspace }))
end
