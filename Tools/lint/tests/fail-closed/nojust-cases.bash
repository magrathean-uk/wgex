# Executed only with the isolated probe shim first on PATH; J3 is scanned, never executed.
own() { "$@"; }
expect() { shift 4; "$@"; }
case "$1" in
  J1)
    helper() {
      just lint
    }
    helper
    ;;
  J2) own just  lint ;;
  J3) own zsh -lc 'bash Tools/lint/lint.sh' ;;
  J5) own just --justfile justfile lint ;;
  J6)
    if true; then
      expect probe fail x - own just lint
    fi
    ;;
  J8)
    J=just
    own "$J" lint
    ;;
  *) exit 99 ;;
esac
