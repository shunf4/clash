@rem @echo off
@goto :runbat_start

# ./build.sh
go build -v -o ./clashmain.exe
./clashmain.exe -d ./test-config/real

exit 0
:runbat_start
@rem @title Busybox Wrapper Program
@cls
@busybox ash -c "EXIT_CODE=0; APP_NAME=MihomoTestIntra; echo -en \"\\033]0;R:[${APP_NAME}]\\a\"; cd \"$(dirname '%~dpnx0')\"; CURR_SCRIPT_PATH='%~dpnx0' ash <(cat '%~dpnx0' | tail -n +3) || { EXIT_CODE=$? ; } ; echo ; echo ================; if [ $EXIT_CODE != 0 ]; then [ -t 1 ] && echo -en \"\\033]0;E:[${APP_NAME}]\\a\"; read -p \"Error code ${EXIT_CODE}, pausing...\"; read; exit 1; else [ -t 1 ] && echo -en \"\\033]0;OK:[${APP_NAME}]\\a\"; read -n1 -p \"Waiting 4 secs, Ctrl+C or Enter to exit now, input to pause...\" -t 4 SHOULD_PAUSE && [ -n \"$SHOULD_PAUSE\" ] || exit 0 ; echo; read -p Pausing...; read; exit 0; fi ; exit 0"
