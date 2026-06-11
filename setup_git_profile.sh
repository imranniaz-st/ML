#!/usr/bin/env bash
# setup_git_profile.sh
# Usage: ./setup_git_profile.sh "Full Name" "email@example.com"
# If no args provided, defaults to repo owner ADC212006

DEFAULT_NAME="ADC212006"
DEFAULT_EMAIL="ADC212006@users.noreply.github.com"

NAME="${1:-$DEFAULT_NAME}"
EMAIL="${2:-$DEFAULT_EMAIL}"

git config user.name "$NAME"
git config user.email "$EMAIL"

echo "Git profile set: $(git config user.name) <$(git config user.email)>"
