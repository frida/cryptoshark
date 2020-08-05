#!/usr/bin/env bash

unameOut="$(uname -s)"
case "${unameOut}" in
    Linux*)     machine=Linux;;
    Darwin*)    machine=Mac;;
    CYGWIN*)    machine=Cygwin;;
    MINGW*)     machine=MinGw;;
    *)          machine="UNKNOWN:${unameOut}"
esac
echo ${machine}

if [ "$machine" = "Linux" ]; then
    sudo apt install qt5-default qtdeclarative5-dev
elif [ "$machine" = "Mac" ]; then
    echo "macos!"
fi

