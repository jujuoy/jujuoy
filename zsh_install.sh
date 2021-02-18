#!/bin/bash

Green_font_prefix="\033[32m"
Red_font_prefix="\033[31m"
Green_background_prefix="\033[42;37m"
Red_background_prefix="\033[41;37m"
Font_color_suffix="\033[0m"
Info="[${Green_font_prefix}信息${Font_color_suffix}]"
Error="[${Red_font_prefix}错误${Font_color_suffix}]"
Tip="[${Green_font_prefix}注意${Font_color_suffix}]"

apt update
check_exist(){
	check_item=$(which $1)
	if [[ $check_item =~ "$1" ]];then
		return 1
	else
		return 0
	fi
}

check_exist "zsh"
if [[ $? != 0 ]];then
	echo "zsh已安装"
else
	echo "zsh未安装，准备安装..."
	apt install zsh -y
fi
echo "开始安装oh_my_zsh...."

check_exist "curl"

if [[ $? != 0 ]];then
	echo "curl已安装"
else
	echo "curl未安装，准备安装..."
	apt install curl -y
fi

set -e
cd ~
chsh -s /bin/zsh
sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)" || { echo "${Error} 安装oh_my_zsh时出错";exit 1;}
perl -i -pe "s/(^ZSH_THEME.*?=.*?\")(.*?)(\")/\1agnoster\3/gi" ~/.zshrc
#安装语法高亮
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting
#自动补全
git clone https://github.com/zsh-users/zsh-autosuggestions $ZSH_CUSTOM/plugins/zsh-autosuggestions
#自动跳转
# clone 到本地
git clone https://github.com/wting/autojump.git ~/autojump
# 进入clone目录，接着执行安装文件
cd ~/autojump
./install.py
# 接着根据安装完成后的提示，在~/.bashrc最后添加下面语句：
echo "[[ -s /home/xxxx/.autojump/etc/profile.d/autojump.sh ]] && source /home/xxxx/.autojump/etc/profile.d/autojump.sh
autoload -U compinit && compinit -u" >> ~/.zshrc
perl -0777 -i -pe "s/(^plugins=\()[\w\W]*(\))/\1git\n\tautojump\n\tzsh-autosuggestions\n\tzsh-syntax-highlighting\n\2/gm" ~/.zshrc
set +e
echo "oh_my_zsh已经成功安装"