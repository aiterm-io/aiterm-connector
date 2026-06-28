# AITerm OSC-133 shell integration for zsh — loaded via ZDOTDIR.
#
# Hermetic: sources the user's own zsh config FIRST (from their original
# ZDOTDIR or $HOME), then layers on nonce-tagged FinalTerm/OSC-133 semantic
# prompt markers using zsh's native precmd/preexec hooks. Never edits the
# user's dotfiles. Markers: C = command started, D = command finished,
# A/B = prompt start/end. The nonce stops a command's output from spoofing a
# "done". AITerm derives: C → WORKING; D/B → IDLE.

# 1) Load the user's normal interactive config from its ORIGINAL location.
__aiterm_uz="${AITERM_ZDOTDIR_ORIG:-$HOME}"
[[ -f /etc/zsh/zshrc ]] && source /etc/zsh/zshrc 2>/dev/null
[[ -f "$__aiterm_uz/.zshrc" ]] && source "$__aiterm_uz/.zshrc" 2>/dev/null

# 2) Layer markers via the native hooks (robust against prompt themes — these
#    persist even when a theme rewrites PS1 on every prompt).
__aiterm_n="${AITERM_OSC133_NONCE:-}"
if [[ -n "$__aiterm_n" && -z "${__aiterm_osc133_on:-}" ]]; then
  __aiterm_osc133_on=1
  __aiterm_precmd()  { printf '\033]133;D;aiterm=%s;%s\007\033]133;A;aiterm=%s\007' "$__aiterm_n" "$?" "$__aiterm_n"; }
  __aiterm_preexec() { printf '\033]133;C;aiterm=%s\007' "$__aiterm_n"; }
  autoload -Uz add-zsh-hook 2>/dev/null
  if (( ${+functions[add-zsh-hook]} )); then
    add-zsh-hook precmd  __aiterm_precmd
    add-zsh-hook preexec __aiterm_preexec
  else
    typeset -ga precmd_functions preexec_functions
    precmd_functions+=(__aiterm_precmd)
    preexec_functions+=(__aiterm_preexec)
  fi
  # B (prompt end) appended best-effort; D from precmd already signals idle if
  # a theme rewrites PS1 and drops this.
  PS1="$PS1"'%{'$'\033'']133;B;aiterm='"$__aiterm_n"$'\007''%}'
fi
