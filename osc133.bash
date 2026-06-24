# AITerm OSC-133 shell integration — loaded via `bash --rcfile`.
#
# Hermetic: it sources the user's own config FIRST, then layers on nonce-tagged
# FinalTerm/OSC-133 semantic prompt markers so AITerm can tell an idle prompt
# (safe to read aloud + open the mic) from a running command (never read
# mid-thought). It never edits the user's dotfiles (feedback_no_filesystem_automation).
#
# Markers (each carries ;aiterm=<nonce> so a command's own output can't spoof a
# "done" and trick hands-free mode): C = command started, D = command finished,
# A/B = prompt start/end. AITerm derives: last marker C → WORKING; B/D → IDLE.

# 1) Load the user's normal interactive config (login + bashrc), unchanged.
if [ -f /etc/bash.bashrc ]; then . /etc/bash.bashrc; fi
if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc"; fi

# 2) Layer markers on top — only if AITerm passed a nonce, and only once.
__aiterm_n="${AITERM_OSC133_NONCE:-}"
if [ -n "$__aiterm_n" ] && [ -z "${__aiterm_osc133_on:-}" ]; then
  __aiterm_osc133_on=1

  # Runs at the start of every prompt cycle (before PS1): emit D (previous
  # command's exit) and arm the preexec one-shot for the next command.
  __aiterm_precmd() {
    local __ec=$?
    printf '\033]133;D;aiterm=%s;%s\007' "$__aiterm_n" "$__ec"
    __aiterm_armed=1
  }

  # DEBUG fires before every simple command. Emit C exactly once per typed
  # command line: skip while completing, skip the PROMPT_COMMAND machinery
  # itself, and disarm after the first real command so pipelines don't repeat.
  __aiterm_preexec() {
    [ -n "${COMP_LINE:-}" ] && return
    case "$BASH_COMMAND" in __aiterm_precmd|__aiterm_preexec) return;; esac
    if [ -n "${__aiterm_armed:-}" ]; then
      __aiterm_armed=
      printf '\033]133;C;aiterm=%s\007' "$__aiterm_n"
    fi
  }

  trap '__aiterm_preexec' DEBUG
  # Prepend our precmd, preserving any PROMPT_COMMAND the user's rc set.
  if [ -n "${PROMPT_COMMAND:-}" ]; then
    PROMPT_COMMAND="__aiterm_precmd; ${PROMPT_COMMAND}"
  else
    PROMPT_COMMAND="__aiterm_precmd"
  fi
  # Wrap the prompt in A (start) / B (end). \[...\] keeps them zero-width.
  PS1='\[\033]133;A;aiterm='"$__aiterm_n"'\007\]'"${PS1}"'\[\033]133;B;aiterm='"$__aiterm_n"'\007\]'
fi
