#!/bin/bash
check_tmux=$(which tmux)
if [[ $check_tmux =~ "tmux" ]];then
    echo "tmux已安装"
else
    echo "tmux未安装"
    apt update
    apt install tmux -y
    echo "#设置前缀为Ctrl + a
set -g prefix C-a
#解除Ctrl+b 与前缀的对应关系
unbind C-b
#将r 设置为加载配置文件，并显示\"reloaded!\"信息
bind r source-file ~/.tmux.conf \; display \"Reloaded!\"
#up
bind-key k select-pane -U
#down
bind-key j select-pane -D
#left
bind-key h select-pane -L
#right
bind-key l select-pane -R
#select last window
bind-key C-l select-window -l
#copy-mode 将快捷键设置为vi 模式
setw -g mode-keys vi" > ~/.tmux.conf
fi
