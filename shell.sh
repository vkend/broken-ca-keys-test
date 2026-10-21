# The shell the tests run in, like a fresh terminal: check.sh sources it in
# `bash --noprofile --norc`; source it yourself in a new terminal to type the
# commands by hand:
#
#   bash --noprofile --norc
#   source shell.sh
#
# It changes HOME (the throwaway one) and PATH, so use a shell meant for it.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/env.sh"
# A shell started with --noprofile --norc has only the system PATH. No Go on
# it: the Go programs in ~/app are already built.
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PS1='$ ' HISTFILE=/dev/null LANG=en_US.UTF-8
unset PROMPT_COMMAND
cd ~/app
