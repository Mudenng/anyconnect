搭建 Anyconnect
==========

###整理自：<http://imkevin.me/post/80157872840/anyconnect-iphone>

##安装 Ocserv

1. 下载 Ocserv：wget ftp://ftp.infradead.org/pub/ocserv/ocserv-0.8.7.tar.xz
2. 解压：tar xvf ocserv-0.8.7.tar.xz
3. 安装编译依赖：

 	```
 	sudo apt-get install build-essential libwrap0-dev libpam0g-dev libdbus-1-dev \ 
 	libreadline-dev libnl-route-3-dev libprotobuf-c0-dev libpcl1-dev libopts25-dev \ 
    autogen libgnutls28 libgnutls28-dev libseccomp-dev
    ```
     
4. 编译安装： ./configure --prefix=/usr --sysconfdir=/etc && make && sudo make install

##生成证书

1. 创建工作目录：mkdir CA && cd CA
2. 生成CA证书：

	```
	certtool --generate-privkey --outfile ca-key.pem
	vim ca.tmpl
	  
	输入以下内容
	cn = "VPN CA"
	organization = "Mudenng"
	serial = 1
	expiration_days = 3650
	ca
	signing_key
	cert_signing_key
	crl_signing_key
	  
	保存退出文件编辑
	  
	certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca- cert.pem
	```
3. 生成本地服务器证书：

	```
	certtool --generate-privkey --outfile server-key.pem
	
	vim server.tmpl
	
	输入以下内容

	cn = "mudenng.com"
	organization = "Mudenng"
	serial = 2
	expiration_days = 3650
	encryption_key
	signing_key
	tls_www_server

	保存退出文件编辑

	certtool --generate-certificate --load-privkey server-key.pem \
	--load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem \
	--template server.tmpl --outfile server-cert.pem
	```
4. `server-cert.pem` 拷贝到 `/etc/ssl/certs` ; `server-key.pem` 拷贝到 `/etc/ssl/private`

##修改配置文件

1. 切换到 Ocserv 解压的源码目录中
2. 创建目录：sudo mkdir /etc/ocserv
3. 拷贝配置模板：sudo cp doc/sample.config /etc/ocserv/ && sudo mv /etc/ocserv/sample.config /etc/ocserv/ocserv.conf
4. 编辑配置文件：
	
	```
	 vim /etc/ocserv/ocserv.conf
	 
	 修改如下：
	
	 auth = "plain[/etc/ocserv/ocpasswd]"
     #ocserv支持多种认证方式，这是自带的密码认证，使用ocpasswd创建密码文件
	 #ocserv还支持证书认证，可以通过Pluggable Authentication Modules (PAM)使用radius等认证方式
	
	 #证书路径
	 server-cert = /etc/ssl/certs/server-cert.pem
	 server-key = /etc/ssl/private/server-key.pem
	
	 #同一个用户最多同时登陆数
	 max-same-clients = 10 
	
	 #运行组
	 run-as-group = nogroup
	
	 #分配给VPN客户端的IP段
	 ipv4-network = 10.10.0.0
	
	 #DNS
	 dns = 8.8.8.8
	 dns = 8.8.4.4
	
	 #注释掉route的字段，这样表示所有流量都通过 VPN 发送
	 #route = 192.168.1.0/255.255.255.0
	 #route = 192.168.5.0/255.255.255.0
	```
	
##创建用户
```
 #username为你要添加的用户名
 sudo ocpasswd -c /etc/ocserv/ocpasswd username 
```

##修改系统配置
1. 允许转发

	```
	 vim /etc/sysctl.conf
	
	 #修改这行
	 net.ipv4.ip_forward = 1
	 
	 保存退出
	
	 sysctl -p
	```
2. 修改 iptables 规则

	```
	vim /etc/iptables.firewall.rules
	
	输入以下：
	
	 *filter

	 #  Allow all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
	 -A INPUT -i lo -j ACCEPT
	 -A INPUT -d 127.0.0.0/8 -j REJECT
	
	 #  Accept all established inbound connections
	 -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	
	 #  Allow all outbound traffic - you can modify this to only allow certain traffic
	 -A OUTPUT -j ACCEPT
	
	 #  Allow HTTP and HTTPS connections from anywhere (the normal ports for websites and SSL).
	 -A INPUT -p tcp --dport 80 -j ACCEPT
	 -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
	 #  Allow SSH connections
	 #
	 #  The -dport number should be the same port number you set in sshd_config
	 #
	 -A INPUT -p tcp -m state --state NEW --dport 22 -j ACCEPT
	
	 #  Allow ping
	 -A INPUT -p icmp -j ACCEPT
	
	 #  Log iptables denied calls
	 -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7
	
	 -A INPUT -j DROP
	
	 COMMIT
	 
	保存退出
	
		！！！特别需要主意的是，一定不要存在这样的一句话，不然能连上也是哪里都不能访问：
		     -A FORWARD -j DROP #不要存在这句
	
	激活 iptables 配置：
	sudo iptables-restore < /etc/iptables.firewall.rules
	
	加入启动配置，每次重启时激活 iptables：
	sudo vim /etc/network/if-pre-up.d/firewal
	
	输入：
	 #!/bin/sh 
	 /sbin/iptables-restore < /etc/iptables.firewall.rules
	 
	修改权限：
	sudo chmod +x /etc/network/if-pre-up.d/firewall
	
	```
	
3. 开启 NAT

	```
	sudo vim /etc/rc.local
	
	在 exit 前加上：
	
	iptables -t nat -A POSTROUTING -j MASQUERADE
	iptables -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 
	
	保存退出
	```
	
##测试服务
1. 开启服务：sudo ocserv -c /etc/ocserv/ocserv.conf -f -d 1
2. 在手机上开启 Anyconnect 客户端，输入服务器地址、用户名密码，看看 Debug 信息

##配置启动
1. 下载：https://gist.github.com/kevinzhow/9661623
2. 文件移动到 `/etc/init.d/ocserv` 下
3. 执行：

	```
	sudo chmod 755 /etc/init.d/ocserv
	sudo update-rc.d ocserv defaults
	```
4. 以后就可以通过 `/etc/init.d/ocserv start` 来管理了

##下发路由
```
sudo vim /etc/ocserv/ocserv.conf

修改 route = xx 的字段

在网上找个路由表，将内容复制，保存后重新服务器即可：
/etc/init.d/ocserv restart

路由表：
https://gist.github.com/kevinzhow/9661732
https://gist.github.com/bao3/bc717ec2294257209c30
```
