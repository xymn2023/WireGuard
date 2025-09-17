#!/bin/bash
#
# https://github.com/hwdsl2/wireguard-install
#
# Based on the work of Nyr and contributors at:
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2022-2025 Lin Song <linsongui@gmail.com>
# Copyright (c) 2020-2023 Nyr
#
# Released under the MIT License, see the accompanying file LICENSE.txt
# or https://opensource.org/licenses/MIT

exiterr()  { echo "错误：$1" >&2; exit 1; }
exiterr2() { exiterr "'apt-get install' 执行失败。"; }
exiterr3() { exiterr "'yum install' 执行失败。"; }
exiterr4() { exiterr "'zypper install' 执行失败。"; }

check_ip() {
	IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_pvt_ip() {
	IPP_REGEX='^(10|127|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168|169\.254)\.'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$IPP_REGEX"
}

check_dns_name() {
	FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
	printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_root() {
	if [ "$(id -u)" != 0 ]; then
			exiterr "必须以 root 身份运行此安装程序。请尝试：sudo bash $0"
	fi
}

check_shell() {
	# Detect Debian users running the script with "sh" instead of bash
	if readlink /proc/$$/exe | grep -q "dash"; then
			exiterr '此安装程序需要使用 "bash" 运行，而不是 "sh"。'
	fi
}

check_kernel() {
	# Detect OpenVZ 6
	if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
			exiterr "系统正在运行过旧的内核，与此安装程序不兼容。"
	fi
}

check_os() {
	if grep -qs "ubuntu" /etc/os-release; then
		os="ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	elif [[ -e /etc/debian_version ]]; then
		os="debian"
		os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
		os="centos"
		os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
	elif [[ -e /etc/fedora-release ]]; then
		os="fedora"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	elif [[ -e /etc/SUSE-brand && "$(head -1 /etc/SUSE-brand)" == "openSUSE" ]]; then
		os="openSUSE"
		os_version=$(tail -1 /etc/SUSE-brand | grep -oE '[0-9\\.]+')
		else
			exiterr "此安装程序似乎运行在不受支持的发行版上。
支持的发行版包括 Ubuntu、Debian、AlmaLinux、Rocky Linux、CentOS、Fedora 和 openSUSE。"
	fi
}

check_os_ver() {
		if [[ "$os" == "ubuntu" && "$os_version" -lt 2004 ]]; then
			exiterr "使用此安装程序需要 Ubuntu 20.04 或更高版本。
当前 Ubuntu 版本过旧且不受支持。"
	fi
		if [[ "$os" == "debian" && "$os_version" -lt 11 ]]; then
			exiterr "使用此安装程序需要 Debian 11 或更高版本。
当前 Debian 版本过旧且不受支持。"
	fi
		if [[ "$os" == "centos" && "$os_version" -lt 8 ]]; then
			exiterr "使用此安装程序需要 CentOS 8 或更高版本。
当前 CentOS 版本过旧且不受支持。"
	fi
}

check_container() {
	if systemd-detect-virt -cq 2>/dev/null; then
			exiterr "系统运行在容器环境中，此安装程序不支持容器内安装。"
	fi
}

set_client_name() {
	# Allow a limited set of characters to avoid conflicts
	# Limit to 15 characters for compatibility with Linux clients
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case $1 in
			--auto)
				auto=1
				shift
				;;
			--addclient)
				add_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--listclients)
				list_clients=1
				shift
				;;
			--removeclient)
				remove_client=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--showclientqr)
				show_client_qr=1
				unsanitized_client="$2"
				shift
				shift
				;;
			--uninstall)
				remove_wg=1
				shift
				;;
			--serveraddr)
				server_addr="$2"
				shift
				shift
				;;
			--port)
				server_port="$2"
				shift
				shift
				;;
			--clientname)
				first_client_name="$2"
				shift
				shift
				;;
			--dns1)
				dns1="$2"
				shift
				shift
				;;
			--dns2)
				dns2="$2"
				shift
				shift
				;;
			-y|--yes)
				assume_yes=1
				shift
				;;
			-h|--help)
				show_usage
				;;
			*)
				show_usage "Unknown parameter: $1"
				;;
		esac
	done
}

check_args() {
	if [ "$auto" != 0 ] && [ -e "$WG_CONF" ]; then
		show_usage "Invalid parameter '--auto'. WireGuard is already set up on this server."
	fi
	if [ "$((add_client + list_clients + remove_client + show_client_qr))" -gt 1 ]; then
		show_usage "Invalid parameters. Specify only one of '--addclient', '--listclients', '--removeclient' or '--showclientqr'."
	fi
	if [ "$remove_wg" = 1 ]; then
		if [ "$((add_client + list_clients + remove_client + show_client_qr + auto))" -gt 0 ]; then
			show_usage "Invalid parameters. '--uninstall' cannot be specified with other parameters."
		fi
	fi
	if [ ! -e "$WG_CONF" ]; then
		st_text="You must first set up WireGuard before"
		[ "$add_client" = 1 ] && exiterr "$st_text adding a client."
		[ "$list_clients" = 1 ] && exiterr "$st_text listing clients."
		[ "$remove_client" = 1 ] && exiterr "$st_text removing a client."
		[ "$show_client_qr" = 1 ] && exiterr "$st_text showing QR code for a client."
		[ "$remove_wg" = 1 ] && exiterr "Cannot remove WireGuard because it has not been set up on this server."
	fi
	if [ "$((add_client + remove_client + show_client_qr))" = 1 ] && [ -n "$first_client_name" ]; then
		show_usage "Invalid parameters. '--clientname' can only be specified when installing WireGuard."
	fi
	if [ -n "$server_addr" ] || [ -n "$server_port" ] || [ -n "$first_client_name" ]; then
			if [ -e "$WG_CONF" ]; then
				show_usage "Invalid parameters. WireGuard is already set up on this server."
			elif [ "$auto" = 0 ]; then
				show_usage "Invalid parameters. You must specify '--auto' when using these parameters."
			fi
	fi
	if [ "$add_client" = 1 ]; then
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		elif grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "$client: invalid name. Client already exists."
		fi
	fi
	if [ "$remove_client" = 1 ] || [ "$show_client_qr" = 1 ]; then
		set_client_name
		if [ -z "$client" ] || ! grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; then
			exiterr "Invalid client name, or client does not exist."
		fi
	fi
	if [ -n "$server_addr" ] && { ! check_dns_name "$server_addr" && ! check_ip "$server_addr"; }; then
		exiterr "Invalid server address. Must be a fully qualified domain name (FQDN) or an IPv4 address."
	fi
	if [ -n "$first_client_name" ]; then
		unsanitized_client="$first_client_name"
		set_client_name
		if [ -z "$client" ]; then
			exiterr "Invalid client name. Use one word only, no special characters except '-' and '_'."
		fi
	fi
	if [ -n "$server_port" ]; then
		if [[ ! "$server_port" =~ ^[0-9]+$ || "$server_port" -gt 65535 ]]; then
			exiterr "Invalid port. Must be an integer between 1 and 65535."
		fi
	fi
	if [ -n "$dns1" ]; then
		if [ -e "$WG_CONF" ] && [ "$add_client" = 0 ]; then
			show_usage "Invalid parameters. Custom DNS server(s) can only be specified when installing WireGuard or adding a client."
		fi
	fi
	if { [ -n "$dns1" ] && ! check_ip "$dns1"; } \
		|| { [ -n "$dns2" ] && ! check_ip "$dns2"; }; then
		exiterr "Invalid DNS server(s)."
	fi
	if [ -z "$dns1" ] && [ -n "$dns2" ]; then
		show_usage "Invalid DNS server. --dns2 cannot be specified without --dns1."
	fi
	if [ -n "$dns1" ] && [ -n "$dns2" ]; then
		dns="$dns1, $dns2"
	elif [ -n "$dns1" ]; then
		dns="$dns1"
	else
		dns="8.8.8.8, 8.8.4.4"
	fi
}

check_nftables() {
	if [ "$os" = "centos" ]; then
		if grep -qs "hwdsl2 VPN script" /etc/sysconfig/nftables.conf \
			|| systemctl is-active --quiet nftables 2>/dev/null; then
			exiterr "This system has nftables enabled, which is not supported by this installer."
		fi
	fi
}

install_wget() {
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		if [ "$auto" = 0 ]; then
            echo "此安装程序需要 Wget。"
            read -n1 -r -p "按任意键安装 Wget 并继续..."
		fi
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wget >/dev/null
		) || exiterr2
	fi
}

install_iproute() {
	if ! hash ip 2>/dev/null; then
		if [ "$auto" = 0 ]; then
            echo "此安装程序需要 iproute。"
            read -n1 -r -p "按任意键安装 iproute 并继续..."
		fi
		if [ "$os" = "debian" ] || [ "$os" = "ubuntu" ]; then
			export DEBIAN_FRONTEND=noninteractive
			(
				set -x
				apt-get -yqq update || apt-get -yqq update
				apt-get -yqq install iproute2 >/dev/null
			) || exiterr2
		elif [ "$os" = "openSUSE" ]; then
			(
				set -x
				zypper install iproute2 >/dev/null
			) || exiterr4
		else
			(
				set -x
				yum -y -q install iproute >/dev/null
			) || exiterr3
		fi
	fi
}

show_header() {
cat <<'EOF'

WireGuard 安装脚本
https://github.com/hwdsl2/wireguard-install
EOF
}

show_header2() {
cat <<'EOF'

欢迎使用 WireGuard 服务器安装程序！
GitHub: https://github.com/hwdsl2/wireguard-install

EOF
}

show_header3() {
cat <<'EOF'

Copyright (c) 2022-2025 Lin Song
Copyright (c) 2020-2023 Nyr
EOF
}

show_usage() {
		if [ -n "$1" ]; then
			echo "错误：$1" >&2
	fi
	show_header
	show_header3
cat 1>&2 <<EOF

用法：bash $0 [选项]

常用选项：

  --addclient [客户端名称]       添加新客户端
  --dns1 [DNS 服务器 IP]         新客户端的主 DNS 服务器（可选，默认：Google 公共 DNS）
  --dns2 [DNS 服务器 IP]         新客户端的次 DNS 服务器（可选）
  --listclients                  列出现有客户端名称
  --removeclient [客户端名称]    删除已有客户端
  --showclientqr [客户端名称]    显示已有客户端的二维码
  --uninstall                    移除 WireGuard 并删除所有配置
  -y, --yes                      在删除客户端或卸载时对提示默认回答“yes”
  -h, --help                     显示本帮助并退出

安装相关选项（可选）：

  --auto                         使用默认或自定义参数自动安装 WireGuard
  --serveraddr [DNS 名称或 IP]   服务器地址，需为完整域名 (FQDN) 或 IPv4 地址
  --port [数字]                  WireGuard 端口（1-65535，默认：51820）
  --clientname [客户端名称]      首个 WireGuard 客户端的名称（默认：client）
  --dns1 [DNS 服务器 IP]         首个客户端的主 DNS（默认：Google 公共 DNS）
  --dns2 [DNS 服务器 IP]         首个客户端的次 DNS

如需自定义选项，也可不带参数直接运行此脚本。
EOF
	exit 1
}

show_welcome() {
	if [ "$auto" = 0 ]; then
        show_header2
        echo '开始安装前需要回答几个问题。'
        echo '你可以直接使用默认选项，按回车确认。'
	else
		show_header
		op_text=default
		if [ -n "$server_addr" ] || [ -n "$server_port" ] \
			|| [ -n "$first_client_name" ] || [ -n "$dns1" ]; then
			op_text=custom
		fi
		echo
        echo "正在使用 $op_text 选项开始配置 WireGuard。"
	fi
}

show_dns_name_note() {
cat <<EOF

Note: Make sure this DNS name '$1'
      resolves to the IPv4 address of this server.
EOF
}

enter_server_address() {
	echo
    echo "是否希望 WireGuard 客户端通过 DNS 名称连接此服务器，"
    printf "例如 vpn.example.com，而不是使用其 IP 地址？[y/N] "
	read -r response
	case $response in
		[yY][eE][sS]|[yY])
			use_dns_name=1
			echo
			;;
		*)
			use_dns_name=0
			;;
	esac
	if [ "$use_dns_name" = 1 ]; then
        read -rp "请输入此 VPN 服务器的 DNS 名称：" server_addr_i
		until check_dns_name "$server_addr_i"; do
            echo "无效的 DNS 名称。必须输入完整域名 (FQDN)。"
            read -rp "请输入此 VPN 服务器的 DNS 名称：" server_addr_i
		done
		ip="$server_addr_i"
		show_dns_name_note "$ip"
	else
		detect_ip
		check_nat_ip
	fi
}

find_public_ip() {
	ip_url1="http://ipv4.icanhazip.com"
	ip_url2="http://ip1.dynupdate.no-ip.com"
	# Get public IP and sanitize with grep
	get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url1" || curl -m 10 -4Ls "$ip_url1")")
	if ! check_ip "$get_public_ip"; then
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "$ip_url2" || curl -m 10 -4Ls "$ip_url2")")
	fi
}

detect_ip() {
	# If system has a single IPv4, it is selected automatically.
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		# Use the IP address on the default route
		ip=$(ip -4 route get 1 | sed 's/ uid .*//' | awk '{print $NF;exit}' 2>/dev/null)
		if ! check_ip "$ip"; then
			find_public_ip
			ip_match=0
			if [ -n "$get_public_ip" ]; then
				ip_list=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
				while IFS= read -r line; do
					if [ "$line" = "$get_public_ip" ]; then
						ip_match=1
						ip="$line"
					fi
				done <<< "$ip_list"
			fi
			if [ "$ip_match" = 0 ]; then
				if [ "$auto" = 0 ]; then
					echo
                    echo "请选择要使用的 IPv4 地址："
					num_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
					ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
                    read -rp "IPv4 地址编号 [1]：" ip_num
					until [[ -z "$ip_num" || "$ip_num" =~ ^[0-9]+$ && "$ip_num" -le "$num_of_ip" ]]; do
                        echo "$ip_num: 非法选择。"
                        read -rp "IPv4 地址编号 [1]：" ip_num
					done
					[[ -z "$ip_num" ]] && ip_num=1
				else
					ip_num=1
				fi
				ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_num"p)
			fi
		fi
	fi
    if ! check_ip "$ip"; then
        echo "错误：无法检测到此服务器的 IP 地址。" >&2
        echo "已中止。未进行任何更改。" >&2
		exit 1
	fi
}

check_nat_ip() {
	# If $ip is a private IP address, the server must be behind NAT
	if check_pvt_ip "$ip"; then
		find_public_ip
		if ! check_ip "$get_public_ip"; then
			if [ "$auto" = 0 ]; then
				echo
                echo "此服务器位于 NAT 之后。请输入公网 IPv4 地址："
                read -rp "公网 IPv4 地址：" public_ip
				until check_ip "$public_ip"; do
                    echo "输入无效。"
                    read -rp "公网 IPv4 地址：" public_ip
				done
			else
                echo "错误：无法检测到此服务器的公网 IP。" >&2
                echo "已中止。未进行任何更改。" >&2
				exit 1
			fi
		else
			public_ip="$get_public_ip"
		fi
	fi
}

show_config() {
	if [ "$auto" != 0 ]; then
		echo
		if [ -n "$server_addr" ]; then
            echo "服务器地址：$server_addr"
		else
            printf '%s' "服务器 IP："
			[ -n "$public_ip" ] && printf '%s\n' "$public_ip" || printf '%s\n' "$ip"
		fi
		[ -n "$server_port" ] && port_text="$server_port" || port_text=51820
		[ -n "$first_client_name" ] && client_text="$client" || client_text=client
		if [ -n "$dns1" ] && [ -n "$dns2" ]; then
			dns_text="$dns1, $dns2"
		elif [ -n "$dns1" ]; then
			dns_text="$dns1"
		else
			dns_text="Google Public DNS"
		fi
        echo "端口：UDP/$port_text"
        echo "客户端名称：$client_text"
        echo "客户端 DNS：$dns_text"
	fi
}

detect_ipv6() {
	ip6=""
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -ne 0 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n 1p)
	fi
}

select_port() {
	if [ "$auto" = 0 ]; then
		echo
        echo "WireGuard 监听哪个端口？"
        read -rp "端口 [51820]：" port
		until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
            echo "$port: 非法端口。"
            read -rp "端口 [51820]：" port
		done
		[[ -z "$port" ]] && port=51820
	else
		[ -n "$server_port" ] && port="$server_port" || port=51820
	fi
}

enter_custom_dns() {
read -rp "请输入主 DNS 服务器：" dns1
	until check_ip "$dns1"; do
    echo "无效的 DNS 服务器。"
    read -rp "请输入主 DNS 服务器：" dns1
	done
read -rp "请输入次 DNS 服务器（回车跳过）：" dns2
	until [ -z "$dns2" ] || check_ip "$dns2"; do
    echo "无效的 DNS 服务器。"
    read -rp "请输入次 DNS 服务器（回车跳过）：" dns2
	done
}

enter_first_client_name() {
	if [ "$auto" = 0 ]; then
		echo
        echo "请输入首个客户端的名称："
        read -rp "名称 [client]：" unsanitized_client
		set_client_name
		[[ -z "$client" ]] && client=client
	else
		if [ -n "$first_client_name" ]; then
			unsanitized_client="$first_client_name"
			set_client_name
		else
			client=client
		fi
	fi
}

show_setup_ready() {
	if [ "$auto" = 0 ]; then
		echo
        echo "已准备开始安装 WireGuard。"
	fi
}

check_firewall() {
	# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "openSUSE" ]]; then
			firewall="firewalld"
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
		if [[ "$firewall" == "firewalld" ]]; then
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo
			echo "注意：为管理路由表所需的 firewalld 也将被安装。"
		fi
	fi
}

abort_and_exit() {
    echo "已中止。未进行任何更改。" >&2
	exit 1
}

confirm_setup() {
	if [ "$auto" = 0 ]; then
        printf "是否继续？[Y/n] "
		read -r response
		case $response in
			[yY][eE][sS]|[yY]|'')
				:
				;;
			*)
				abort_and_exit
				;;
		esac
	fi
}

show_start_setup() {
    echo
    echo "正在安装 WireGuard，请稍候..."
}

install_pkgs() {
	if [[ "$os" == "ubuntu" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" == "debian" ]]; then
		export DEBIAN_FRONTEND=noninteractive
		(
			set -x
			apt-get -yqq update || apt-get -yqq update
			apt-get -yqq install wireguard qrencode $firewall >/dev/null
		) || exiterr2
	elif [[ "$os" == "centos" && "$os_version" -ge 9 ]]; then
		(
			set -x
			yum -y -q install epel-release >/dev/null
			yum -y -q install wireguard-tools qrencode $firewall >/dev/null 2>&1
		) || exiterr3
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
		(
			set -x
			yum -y -q install epel-release elrepo-release >/dev/null
			yum -y -q --nobest install kmod-wireguard >/dev/null 2>&1
			yum -y -q install wireguard-tools qrencode $firewall >/dev/null 2>&1
		) || exiterr3
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "fedora" ]]; then
		(
			set -x
			dnf install -y wireguard-tools qrencode $firewall >/dev/null
        ) || exiterr "'dnf install' 执行失败。"
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "openSUSE" ]]; then
		(
			set -x
			zypper install -y wireguard-tools qrencode $firewall >/dev/null
		) || exiterr4
		mkdir -p /etc/wireguard/
	fi
	[ ! -d /etc/wireguard ] && exiterr2
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		(
			set -x
			systemctl enable --now firewalld.service >/dev/null 2>&1
		)
	fi
}

remove_pkgs() {
	if [[ "$os" == "ubuntu" ]]; then
		(
			set -x
			rm -rf /etc/wireguard/
			apt-get remove --purge -y wireguard wireguard-tools >/dev/null
		)
	elif [[ "$os" == "debian" ]]; then
		(
			set -x
			rm -rf /etc/wireguard/
			apt-get remove --purge -y wireguard wireguard-tools >/dev/null
		)
	elif [[ "$os" == "centos" && "$os_version" -ge 9 ]]; then
		(
			set -x
			yum -y -q remove wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
		(
			set -x
			yum -y -q remove kmod-wireguard wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	elif [[ "$os" == "fedora" ]]; then
		(
			set -x
			dnf remove -y wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	elif [[ "$os" == "openSUSE" ]]; then
		(
			set -x
			zypper remove -y wireguard-tools >/dev/null
			rm -rf /etc/wireguard/
		)
	fi
}

create_server_config() {
	# Generate wg0.conf
	cat << EOF > "$WG_CONF"
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 "$WG_CONF"
}

create_firewall_rules() {
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld reload
		firewall-cmd -q --add-port="$port"/udp
		firewall-cmd -q --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd -q --permanent --add-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --add-source=10.7.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd -q --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		if [[ -n "$ip6" ]]; then
			firewall-cmd -q --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		(
			set -x
			systemctl enable --now wg-iptables.service >/dev/null 2>&1
		)
	fi
}

remove_firewall_rules() {
	port=$(grep '^ListenPort' "$WG_CONF" | cut -d " " -f 3)
	if systemctl is-active --quiet firewalld.service; then
		ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
		# Using both permanent and not permanent rules to avoid a firewalld reload.
		firewall-cmd -q --remove-port="$port"/udp
		firewall-cmd -q --zone=trusted --remove-source=10.7.0.0/24
		firewall-cmd -q --permanent --remove-port="$port"/udp
		firewall-cmd -q --permanent --zone=trusted --remove-source=10.7.0.0/24
		firewall-cmd -q --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		firewall-cmd -q --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j MASQUERADE
		if grep -qs 'fddd:2c4:2c4:2c4::1/64' "$WG_CONF"; then
			ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:2c4:2c4:2c4::/64 '"'"'!'"'"' -d fddd:2c4:2c4:2c4::/64' | grep -oE '[^ ]+$')
			firewall-cmd -q --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd -q --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
			firewall-cmd -q --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j MASQUERADE
		fi
	else
		systemctl disable --now wg-iptables.service
		rm -f /etc/systemd/system/wg-iptables.service
	fi
}

get_export_dir() {
	export_to_home_dir=0
	export_dir=~/
	if [ -n "$SUDO_USER" ] && getent group "$SUDO_USER" >/dev/null 2>&1; then
		user_home_dir=$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6)
		if [ -d "$user_home_dir" ] && [ "$user_home_dir" != "/" ]; then
			export_dir="$user_home_dir/"
			export_to_home_dir=1
		fi
	fi
}

select_dns() {
	if [ "$auto" = 0 ]; then
		echo
        echo "为客户端选择 DNS 服务器："
        echo "   1) 当前系统解析器"
        echo "   2) Google 公共 DNS"
        echo "   3) Cloudflare DNS"
        echo "   4) OpenDNS"
        echo "   5) Quad9"
        echo "   6) AdGuard DNS"
        echo "   7) 自定义"
		read -rp "DNS server [2]: " dns
		until [[ -z "$dns" || "$dns" =~ ^[1-7]$ ]]; do
            echo "$dns: 非法选择。"
			read -rp "DNS server [2]: " dns
		done
	else
		dns=2
	fi
		# DNS
	case "$dns" in
		1)
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2|"")
			dns="8.8.8.8, 8.8.4.4"
		;;
		3)
			dns="1.1.1.1, 1.0.0.1"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="9.9.9.9, 149.112.112.112"
		;;
		6)
			dns="94.140.14.14, 94.140.15.15"
		;;
		7)
			enter_custom_dns
			if [ -n "$dns2" ]; then
				dns="$dns1, $dns2"
			else
				dns="$dns1"
			fi
		;;
	esac
}

select_client_ip() {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		exiterr "253 clients are already configured. The WireGuard internal subnet is full!"
	fi
}

new_client() {
	select_client_ip
	specify_ip=n
    if [ "$1" = "add_client" ] && [ "$add_client" = 0 ]; then
		echo
        read -rp "是否为新客户端指定内网 IP 地址？[y/N]：" specify_ip
		until [[ "$specify_ip" =~ ^[yYnN]*$ ]]; do
            echo "$specify_ip: 非法选择。"
            read -rp "是否为新客户端指定内网 IP 地址？[y/N]：" specify_ip
		done
		if [[ ! "$specify_ip" =~ ^[yY]$ ]]; then
            echo "将使用自动分配的 IP 地址 10.7.0.$octet。"
		fi
	fi
	if [[ "$specify_ip" =~ ^[yY]$ ]]; then
		echo
        read -rp "请输入新客户端的 IP 地址（例如 10.7.0.X）：" client_ip
		octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		until [[ $client_ip =~ ^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]] \
			&& ! grep AllowedIPs "$WG_CONF" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
            if [[ ! $client_ip =~ ^10\.7\.0\.([2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$ ]]; then
                echo "无效的 IP 地址。必须位于 10.7.0.2 到 10.7.0.254 之间。"
			else
                echo "该 IP 地址已被使用。请更换一个。"
			fi
            read -rp "请输入新客户端的 IP 地址（例如 10.7.0.X）：" client_ip
			octet=$(printf '%s' "$client_ip" | cut -d "." -f 4)
		done
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> "$WG_CONF"
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< "$key")
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' "$WG_CONF" && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	get_export_dir
	cat << EOF > "$export_dir$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' "$WG_CONF" && echo ", fddd:2c4:2c4:2c4::$octet/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey "$WG_CONF" | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' "$WG_CONF" | cut -d " " -f 3):$(grep ListenPort "$WG_CONF" | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
	if [ "$export_to_home_dir" = 1 ]; then
		chown "$SUDO_USER:$SUDO_USER" "$export_dir$client".conf
	fi
	chmod 600 "$export_dir$client".conf
}

update_sysctl() {
	mkdir -p /etc/sysctl.d
	conf_fwd="/etc/sysctl.d/99-wireguard-forward.conf"
	conf_opt="/etc/sysctl.d/99-wireguard-optimize.conf"
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > "$conf_fwd"
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> "$conf_fwd"
	fi
	# Optimize sysctl settings such as TCP buffer sizes
	base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
	conf_url="$base_url/sysctl-wg-$os"
	[ "$auto" != 0 ] && conf_url="${conf_url}-auto"
	wget -t 3 -T 30 -q -O "$conf_opt" "$conf_url" 2>/dev/null \
		|| curl -m 30 -fsL "$conf_url" -o "$conf_opt" 2>/dev/null \
		|| { /bin/rm -f "$conf_opt"; touch "$conf_opt"; }
	# Enable TCP BBR congestion control if kernel version >= 4.20
	if modprobe -q tcp_bbr \
		&& printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V \
		&& [ -f /proc/sys/net/ipv4/tcp_congestion_control ]; then
cat >> "$conf_opt" <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	fi
	# Apply sysctl settings
	sysctl -e -q -p "$conf_fwd"
	sysctl -e -q -p "$conf_opt"
}

update_rclocal() {
	ipt_cmd="systemctl restart wg-iptables.service"
	if ! grep -qs "$ipt_cmd" /etc/rc.local; then
		if [ ! -f /etc/rc.local ]; then
			echo '#!/bin/sh' > /etc/rc.local
		else
			if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
				sed --follow-symlinks -i '/^exit 0/d' /etc/rc.local
			fi
		fi
cat >> /etc/rc.local <<EOF

$ipt_cmd
EOF
		if [ "$os" = "ubuntu" ] || [ "$os" = "debian" ]; then
			echo "exit 0" >> /etc/rc.local
		fi
		chmod +x /etc/rc.local
	fi
}

start_wg_service() {
	# Enable and start the wg-quick service
	(
		set -x
		systemctl enable --now wg-quick@wg0.service >/dev/null 2>&1
	)
}

show_client_qr_code() {
    qrencode -t UTF8 < "$export_dir$client".conf
    echo -e '\xE2\x86\x91 上方为包含客户端配置的二维码。'
}

finish_setup() {
	echo
    # If the kernel module didn't load, system probably had an outdated kernel
    if ! modprobe -nq wireguard; then
        echo "警告！"
        echo "安装已完成，但无法加载 WireGuard 内核模块。"
        echo "请重启系统以加载最新内核。"
    else
        echo "完成！"
    fi
    echo
    echo "客户端配置文件位置：$export_dir$client.conf"
    echo "可再次运行此脚本添加新客户端。"
}

select_menu_option() {
	echo
	echo "已检测到 WireGuard 已安装。"
	echo
	echo "请选择操作："
	echo "   1) 添加新客户端"
	echo "   2) 列出现有客户端"
	echo "   3) 删除已有客户端"
	echo "   4) 显示客户端二维码"
	echo "   5) 卸载 WireGuard"
	echo "   6) 退出"
	read -rp "选项：" option
	until [[ "$option" =~ ^[1-6]$ ]]; do
		echo "$option: 非法选择。"
		read -rp "选项：" option
	done
}

show_clients() {
	grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | nl -s ') '
}

enter_client_name() {
	echo
	echo "请输入客户端名称："
	read -rp "名称：" unsanitized_client
	[ -z "$unsanitized_client" ] && abort_and_exit
	set_client_name
	while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" "$WG_CONF"; do
		if [ -z "$client" ]; then
			echo "无效的客户端名称。只能使用一个单词，且仅允许 '-' 与 '_'。"
		else
			echo "$client：名称无效。该客户端已存在。"
		fi
		read -rp "名称：" unsanitized_client
		[ -z "$unsanitized_client" ] && abort_and_exit
		set_client_name
	done
}

update_wg_conf() {
	# Append new client configuration to the WireGuard interface
	wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "$WG_CONF")
}

print_client_added() {
	echo
echo "$client 已添加。配置文件位置：$export_dir$client.conf"
}

print_check_clients() {
	echo
echo "正在检查现有客户端..."
}

check_clients() {
	num_of_clients=$(grep -c '^# BEGIN_PEER' "$WG_CONF")
	if [[ "$num_of_clients" = 0 ]]; then
		echo
echo "当前没有任何客户端！"
		exit 1
	fi
}

print_client_total() {
	if [ "$num_of_clients" = 1 ]; then
		printf '\n%s\n' "Total: 1 client"
	elif [ -n "$num_of_clients" ]; then
		printf '\n%s\n' "Total: $num_of_clients clients"
	fi
}

select_client_to() {
	echo
echo "请选择要$1 的客户端："
	show_clients
read -rp "客户端编号：" client_num
	[ -z "$client_num" ] && abort_and_exit
	until [[ "$client_num" =~ ^[0-9]+$ && "$client_num" -le "$num_of_clients" ]]; do
echo "$client_num: 非法选择。"
        read -rp "客户端编号：" client_num
		[ -z "$client_num" ] && abort_and_exit
	done
	client=$(grep '^# BEGIN_PEER' "$WG_CONF" | cut -d ' ' -f 3 | sed -n "$client_num"p)
}

confirm_remove_client() {
	if [ "$assume_yes" != 1 ]; then
		echo
read -rp "确认删除 $client？[y/N]：" remove
		until [[ "$remove" =~ ^[yYnN]*$ ]]; do
        echo "$remove: 非法选择。"
        read -rp "确认删除 $client？[y/N]：" remove
		done
	else
		remove=y
	fi
}

remove_client_conf() {
	get_export_dir
	wg_file="$export_dir$client.conf"
    if [ -f "$wg_file" ]; then
        echo "正在删除 $wg_file..."
		rm -f "$wg_file"
	fi
}

print_remove_client() {
	echo
echo "正在删除 $client..."
}

remove_client_wg() {
	# The following is the right way to avoid disrupting other active connections:
	# Remove from the live interface
	wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" "$WG_CONF" | grep -m 1 PublicKey | cut -d " " -f 3)" remove
	# Remove from the configuration file
	sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "$WG_CONF"
	remove_client_conf
}

print_client_removed() {
	echo
echo "$client 已删除！"
}

print_client_removal_aborted() {
	echo
echo "$client 删除已取消！"
}

check_client_conf() {
	wg_file="$export_dir$client.conf"
	if [ ! -f "$wg_file" ]; then
        echo "错误：无法显示二维码。缺少客户端配置文件 $wg_file" >&2
        echo "       你可以重新运行此脚本以添加新客户端。" >&2
		exit 1
	fi
}

print_client_conf() {
	echo
echo "'$client' 的配置文件位置：$wg_file"
}

confirm_remove_wg() {
	if [ "$assume_yes" != 1 ]; then
		echo
read -rp "确认卸载 WireGuard？[y/N]：" remove
		until [[ "$remove" =~ ^[yYnN]*$ ]]; do
        echo "$remove: 非法选择。"
        read -rp "确认卸载 WireGuard？[y/N]：" remove
		done
	else
		remove=y
	fi
}

print_remove_wg() {
	echo
echo "正在卸载 WireGuard，请稍候..."
}

disable_wg_service() {
	systemctl disable --now wg-quick@wg0.service
}

remove_sysctl_rules() {
	rm -f /etc/sysctl.d/99-wireguard-forward.conf /etc/sysctl.d/99-wireguard-optimize.conf
	if [ ! -f /usr/sbin/openvpn ] && [ ! -f /usr/sbin/ipsec ] \
		&& [ ! -f /usr/local/sbin/ipsec ]; then
		echo 0 > /proc/sys/net/ipv4/ip_forward
		echo 0 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
}

remove_rclocal_rules() {
	ipt_cmd="systemctl restart wg-iptables.service"
	if grep -qs "$ipt_cmd" /etc/rc.local; then
		sed --follow-symlinks -i "/^$ipt_cmd/d" /etc/rc.local
	fi
}

print_wg_removed() {
	echo
echo "WireGuard 已卸载！"
}

print_wg_removal_aborted() {
	echo
echo "已取消卸载 WireGuard！"
}

wgsetup() {

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

check_root
check_shell
check_kernel
check_os
check_os_ver
check_container

WG_CONF="/etc/wireguard/wg0.conf"

auto=0
assume_yes=0
add_client=0
list_clients=0
remove_client=0
show_client_qr=0
remove_wg=0
public_ip=""
server_addr=""
server_port=""
first_client_name=""
unsanitized_client=""
client=""
dns=""
dns1=""
dns2=""

parse_args "$@"
check_args

if [ "$add_client" = 1 ]; then
	show_header
	new_client add_client
	update_wg_conf
	echo
	show_client_qr_code
	print_client_added
	exit 0
fi

if [ "$list_clients" = 1 ]; then
	show_header
	print_check_clients
	check_clients
	echo
	show_clients
	print_client_total
	exit 0
fi

if [ "$remove_client" = 1 ]; then
	show_header
	confirm_remove_client
	if [[ "$remove" =~ ^[yY]$ ]]; then
		print_remove_client
		remove_client_wg
		print_client_removed
		exit 0
	else
		print_client_removal_aborted
		exit 1
	fi
fi

if [ "$show_client_qr" = 1 ]; then
	show_header
	echo
	get_export_dir
	check_client_conf
	show_client_qr_code
	print_client_conf
	exit 0
fi

if [ "$remove_wg" = 1 ]; then
	show_header
	confirm_remove_wg
	if [[ "$remove" =~ ^[yY]$ ]]; then
		print_remove_wg
		remove_firewall_rules
		disable_wg_service
		remove_sysctl_rules
		remove_rclocal_rules
		remove_pkgs
		print_wg_removed
		exit 0
	else
		print_wg_removal_aborted
		exit 1
	fi
fi

if [[ ! -e "$WG_CONF" ]]; then
	check_nftables
	install_wget
	install_iproute
	show_welcome
	if [ "$auto" = 0 ]; then
		enter_server_address
	else
		if [ -n "$server_addr" ]; then
			ip="$server_addr"
		else
			detect_ip
			check_nat_ip
		fi
	fi
	show_config
	detect_ipv6
	select_port
	enter_first_client_name
	if [ "$auto" = 0 ]; then
		select_dns
	fi
	show_setup_ready
	check_firewall
	confirm_setup
	show_start_setup
	install_pkgs
	create_server_config
	update_sysctl
	create_firewall_rules
	if [ "$os" != "openSUSE" ]; then
		update_rclocal
	fi
	new_client
	start_wg_service
	echo
	show_client_qr_code
	if [ "$auto" != 0 ] && check_dns_name "$server_addr"; then
		show_dns_name_note "$server_addr"
	fi
	finish_setup
else
	show_header
	select_menu_option
	case "$option" in
		1)
			enter_client_name
			select_dns
			new_client add_client
			update_wg_conf
			echo
			show_client_qr_code
			print_client_added
			exit 0
		;;
		2)
			print_check_clients
			check_clients
			echo
			show_clients
			print_client_total
			exit 0
		;;
		3)
			check_clients
			select_client_to remove
			confirm_remove_client
			if [[ "$remove" =~ ^[yY]$ ]]; then
				print_remove_client
				remove_client_wg
				print_client_removed
				exit 0
			else
				print_client_removal_aborted
				exit 1
			fi
		;;
		4)
			check_clients
			select_client_to "show QR code for"
			echo
			get_export_dir
			check_client_conf
			show_client_qr_code
			print_client_conf
			exit 0
		;;
		5)
			confirm_remove_wg
			if [[ "$remove" =~ ^[yY]$ ]]; then
				print_remove_wg
				remove_firewall_rules
				disable_wg_service
				remove_sysctl_rules
				remove_rclocal_rules
				remove_pkgs
				print_wg_removed
				exit 0
			else
				print_wg_removal_aborted
				exit 1
			fi
		;;
		6)
			exit 0
		;;
	esac
fi
}

## Defer setup until we have the complete script
wgsetup "$@"

exit 0