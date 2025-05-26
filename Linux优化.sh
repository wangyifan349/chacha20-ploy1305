#!/bin/bash

# 禁止系统自动更新
echo "禁用自动更新..."
sudo bash -c 'echo "APT::Periodic::Update-Package-Lists \"0\";" > /etc/apt/apt.conf.d/20auto-upgrades'
sudo bash -c 'echo "APT::Periodic::Unattended-Upgrade \"0\";" >> /etc/apt/apt.conf.d/20auto-upgrades'

# 禁止虚拟内存（交换空间）
echo "禁用交换空间..."
sudo swapoff -a  # 立即禁用交换
sudo bash -c 'sed -i "/swapfile/d" /etc/fstab'  # 从fstab中删除交换条目

# 禁用家庭组
echo "禁用家庭组..."
sudo bash -c 'echo "[HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System]" >> /etc/sysctl.conf'
sudo bash -c 'echo "EnableLUA=0" >> /etc/sysctl.conf'  # 禁用用户账户控制

# 禁用IPv6
echo "禁用IPv6..."
sudo bash -c 'echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf'
sudo bash -c 'echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf'
sudo bash -c 'echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf'

# 禁用未使用的网络协议（如NetBIOS）
echo "禁用未使用的网络协议..."
sudo bash -c 'echo "netbios name = " >> /etc/samba/smb.conf'  # 清空NetBIOS名称
sudo systemctl stop nmbd  # 停止NetBIOS服务
sudo systemctl disable nmbd  # 禁用NetBIOS服务

# 禁用不必要的服务
# 请根据需要替换service_name为实际服务名
# sudo systemctl disable service_name

# 限制用户权限
echo "创建新用户并限制权限..."
sudo adduser newuser  # 创建新用户
sudo usermod -aG sudo newuser  # 如果需要sudo权限

# 限制最大登录尝试次数
echo "限制SSH登录尝试次数..."
sudo bash -c 'echo "MaxAuthTries 3" >> /etc/ssh/sshd_config'
# 限制最大登录尝试次数
echo "限制SSH登录尝试次数..."
sudo bash -c 'echo "MaxAuthTries 3" >> /etc/ssh/sshd_config'

# 配置防火墙
echo "配置防火墙..."
sudo ufw enable  # 启用防火墙
sudo ufw allow ssh  # 允许SSH连接
sudo ufw deny 23  # 禁止Telnet
sudo ufw deny 80  # 禁止HTTP（如果不需要）
sudo ufw deny 443  # 禁止HTTPS（如果不需要）

# 配置SSH安全性
echo "配置SSH安全性..."
sudo bash -c 'echo "PermitRootLogin no" >> /etc/ssh/sshd_config'  # 禁用root用户SSH登录
sudo bash -c 'echo "PasswordAuthentication no" >> /etc/ssh/sshd_config'  # 禁用密码认证

# 安装并配置Fail2ban
echo "安装并配置Fail2ban..."
sudo apt install -y fail2ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

# 定期更新系统（手动）
echo "请定期手动更新系统..."
echo "使用命令: sudo apt update && sudo apt upgrade"

# 安装并配置auditd
echo "安装并配置系统审计..."
sudo apt install -y auditd
sudo systemctl start auditd
sudo systemctl enable auditd

# 加强内核安全
echo "加强内核安全..."
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space  # 启用地址空间布局随机化
# 加强内存安全
echo "加强内存安全配置..."
# 限制用户的最大内存使用
echo "vm.overcommit_memory=2" | sudo tee -a /etc/sysctl.conf  # 仅在物理内存可用时允许分配
echo "vm.overcommit_ratio=50" | sudo tee -a /etc/sysctl.conf  # 设置内存分配比例
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf  # 减少交换使用
# 1. 仅在物理内存可用时允许分配
echo "vm.overcommit_memory=2" | sudo tee -a /etc/sysctl.conf
# 2. 设置内存分配比例
echo "vm.overcommit_ratio=50" | sudo tee -a /etc/sysctl.conf
# 3. 减少交换使用
echo "vm.swappiness=10" | sudo tee -a /etc/sysctl.conf
# 4. 启用地址空间布局随机化
echo "kernel.randomize_va_space=2" | sudo tee -a /etc/sysctl.conf
# 5. 启用内核堆栈保护
echo "kernel.panic_on_oops=1" | sudo tee -a /etc/sysctl.conf
# 6. 启用内存保护
echo "kernel.exec-shield=1" | sudo tee -a /etc/sysctl.conf
# 7. 启用地址空间布局随机化
echo "kernel.randomize_va_space=2" | sudo tee -a /etc/sysctl.conf
# 8. 限制最大文件句柄数
echo "fs.file-max=100000" | sudo tee -a /etc/sysctl.conf
# 9. 启用TCP SYN Cookie
echo "net.ipv4.tcp_syncookies=1" | sudo tee -a /etc/sysctl.conf
# 10. 限制IP包的转发
echo "net.ipv4.ip_forward=0" | sudo tee -a /etc/sysctl.conf
# 11. 禁用源路由
echo "net.ipv4.conf.all.accept_source_route=0" | sudo tee -a /etc/sysctl.conf
# 12. 禁用ICMP重定向
echo "net.ipv4.conf.all.accept_redirects=0" | sudo tee -a /etc/sysctl.conf
# 13. 禁用IPv4的广播
echo "net.ipv4.conf.all.rp_filter=1" | sudo tee -a /etc/sysctl.conf
# 14. 启用TCP时间戳
echo "net.ipv4.tcp_timestamps=1" | sudo tee -a /etc/sysctl.conf
# 15. 限制TCP连接的最大数量
echo "net.ipv4.tcp_max_syn_backlog=2048" | sudo tee -a /etc/sysctl.conf
# 16. 启用TCP快速打开
echo "net.ipv4.tcp_fastopen=3" | sudo tee -a /etc/sysctl.conf
# 17. 启用TCP窗口缩放
echo "net.ipv4.tcp_window_scaling=1" | sudo tee -a /etc/sysctl.conf
# 18. 启用TCP保活
echo "net.ipv4.tcp_keepalive_time=600" | sudo tee -a /etc/sysctl.conf
# 19. 限制内存映射的最大值
echo "vm.mmap_min_addr=4096" | sudo tee -a /etc/sysctl.conf
# 20. 启用内存页的透明大页
echo "vm.transparent_hugepage=always" | sudo tee -a /etc/sysctl.conf
# 21. 启用内存页的透明大页
echo "vm.dirty_ratio=20" | sudo tee -a /etc/sysctl.conf
# 22. 启用内存页的透明大页
echo "vm.dirty_background_ratio=10" | sudo tee -a /etc/sysctl.conf
# 23. 启用内存页的透明大页
echo "vm.min_free_kbytes=65536" | sudo tee -a /etc/sysctl.conf
# 24. 启用内存页的透明大页
echo "vm.page-cluster=3" | sudo tee -a /etc/sysctl.conf
# 25. 启用内存页的透明大页
echo "vm.vfs_cache_pressure=50" | sudo tee -a /etc/sysctl.conf
# 1. 启用文件系统的安全特性（如ext4）
echo "fs.protected_regular=1" | sudo tee -a /etc/sysctl.conf  # 保护常规文件
echo "fs.protected_fifos=1" | sudo tee -a /etc/sysctl.conf  # 保护FIFO文件
echo "fs.protected_symlinks=1" | sudo tee -a /etc/sysctl.conf  # 保护符号链接
# 2. 限制文件系统的挂载选项
echo "fs.may_detach_mounts=0" | sudo tee -a /etc/sysctl.conf  # 禁止卸载挂载点
# 3. 启用文件系统的只读挂载
echo "mount -o remount,ro /"  # 将根文件系统重新挂载为只读（请谨慎使用）
# 4. 启用文件系统的审计
echo "kernel.audits_enabled=1" | sudo tee -a /etc/sysctl.conf  # 启用审计功能
# 5. 启用文件系统的访问控制
echo "fs.suid_dumpable=0" | sudo tee -a /etc/sysctl.conf  # 禁止SUID程序的核心转储
# 6. 启用文件系统的安全性
echo "fs.file-max=100000" | sudo tee -a /etc/sysctl.conf  # 限制最大文件句柄数
# 7. 启用文件系统的日志记录
echo "fs.journal_data=writeback" | sudo tee -a /etc/sysctl.conf  # 设置日志数据写入方式
# 8. 启用文件系统的透明大页
echo "vm.transparent_hugepage=always" | sudo tee -a /etc/sysctl.conf  # 启用透明大页
# 9. 启用文件系统的写入保护
echo "fs.dentry-state=1" | sudo tee -a /etc/sysctl.conf  # 启用目录项状态保护
# 10. 启用文件系统的内存保护
echo "vm.mmap_min_addr=4096" | sudo tee -a /etc/sysctl.conf  # 限制内存映射的最小值
# 11. 启用文件系统的缓存压力
echo "vm.vfs_cache_pressure=50" | sudo tee -a /etc/sysctl.conf  # 设置VFS缓存压力
# 12. 启用文件系统的写入延迟
echo "vm.dirty_ratio=20" | sudo tee -a /etc/sysctl.conf  # 设置脏页比例
echo "vm.dirty_background_ratio=10" | sudo tee -a /etc/sysctl.conf  # 设置后台脏页比例
# 13. 启用文件系统的最小空闲空间
echo "vm.min_free_kbytes=65536" | sudo tee -a /etc/sysctl.conf  # 设置最小空闲空间
# 14. 启用文件系统的内存映射
echo "vm.page-cluster=3" | sudo tee -a /etc/sysctl.conf  # 设置页面聚集
# 15. 启用文件系统的内存保护
echo "fs.protected_regular=1" | sudo tee -a /etc/sysctl.conf  # 保护常规文件
# 16. 启用文件系统的内存映射
echo "vm.mmap_min_addr=65536" | sudo tee -a /etc/sysctl.conf  # 设置最小内存映射地址
# 17. 启用文件系统的内存保护
echo "fs.suid_dumpable=0" | sudo tee -a /etc/sysctl.conf  # 禁止SUID程序的核心转储
# 18. 启用文件系统的内存保护
echo "fs.protected_fifos=1" | sudo tee -a /etc/sysctl.conf  # 保护FIFO文件
# 19. 启用文件系统的内存保护
echo "fs.protected_symlinks=1" | sudo tee -a /etc/sysctl.conf  # 保护符号链接
# 20. 启用文件系统的内存保护
echo "fs.may_detach_mounts=0" | sudo tee -a /etc/sysctl.conf  # 禁止卸载挂载点







