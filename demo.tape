# VHS tape — IronContext README demo.
#
# Render with:
#     vhs demo.tape
#
# Install VHS if needed:
#     brew install vhs        # macOS
#     go install github.com/charmbracelet/vhs@latest   # any
#
# Produces docs/assets/demo.gif. Paths below are relative to the repo root,
# so always run `vhs demo.tape` from the project root.

Output docs/assets/demo.gif

Set Shell        "bash"
Set FontSize     18
Set Width        1280
Set Height       760
Set Theme        "Catppuccin Mocha"
Set TypingSpeed  50ms
Set Padding      24
Set Margin       0
Set BorderRadius 8
Set LineHeight   1.25

# ── Hidden setup ────────────────────────────────────────────────
# Clean prompt, put the release binary on PATH, and clear the screen
# so the first visible frame is a fresh prompt.
Hide
Type "export PS1='\033[38;5;75m❯\033[0m '"
Enter
Type "export PATH=$PWD/target/release:$PATH"
Enter
Type "clear"
Enter
Show

Sleep 800ms

# ── Scene 1 ─ Security scan on a poisoned MCP server ────────────
Type "ironcontext scan fixtures/demo/poisoned_server.json"
Sleep 600ms
Enter
Sleep 6s

# Hold the [CRIT] findings on screen a beat longer.
Sleep 1500ms

# ── Scene 2 ─ Optimizer reclaims context-window tokens ──────────
Hide
Type "clear"
Enter
Show
Sleep 600ms

Type "ironcontext optimize fixtures/demo/clean_server.json --require-reduction-pct 40"
Sleep 600ms
Enter
Sleep 5s

# ── Scene 3 ─ Latency benchmark, <10ms gate ─────────────────────
Hide
Type "clear"
Enter
Show
Sleep 600ms

Type "ironcontext bench fixtures/large_manifest.json --iterations 300 --budget-ms 10"
Sleep 600ms
Enter
Sleep 4s

# Final beat so the closing frame is readable.
Sleep 1500ms
