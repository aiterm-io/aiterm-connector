# AITerm OSC-133 shell integration for fish — loaded via `fish -C 'source …'`.
#
# fish runs the user's own config.fish BEFORE the -C command, so this file only
# ADDS nonce-tagged FinalTerm/OSC-133 markers via fish's native events; it never
# edits the user's files. Markers: C = command started, D = command finished,
# A/B = prompt start/end. The nonce stops a command's output from spoofing a
# "done". AITerm derives: C → WORKING; D/B → IDLE.

if set -q AITERM_OSC133_NONCE; and not set -q __aiterm_osc133_on
    set -g __aiterm_osc133_on 1
    set -g __aiterm_n $AITERM_OSC133_NONCE

    function __aiterm_preexec --on-event fish_preexec
        printf '\033]133;C;aiterm=%s\007' $__aiterm_n
    end
    function __aiterm_postexec --on-event fish_postexec
        printf '\033]133;D;aiterm=%s;%s\007' $__aiterm_n $status
    end

    # Wrap the existing prompt with A (start) / B (end). Copy the user's
    # fish_prompt aside, then redefine it to bracket the original.
    if functions -q fish_prompt
        functions -c fish_prompt __aiterm_orig_prompt
    end
    function fish_prompt
        printf '\033]133;A;aiterm=%s\007' $__aiterm_n
        if functions -q __aiterm_orig_prompt
            __aiterm_orig_prompt
        else
            printf '%s> ' (prompt_pwd)
        end
        printf '\033]133;B;aiterm=%s\007' $__aiterm_n
    end
end
