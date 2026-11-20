# 模拟受管主机：轻量 SSH 服务器 + 一组模拟高危命令
# 基于 linuxserver/openssh-server，通过环境变量注入登录公钥（见 docker-compose）
FROM linuxserver/openssh-server:latest

USER root

# 模拟数据/审计目录结构（策略规则里引用的真实路径）
RUN mkdir -p /var/lib/mysql /var/lib/postgresql /var/lib/redis /var/lib/mongodb \
             /var/log/audit /data/mysql /etc/cron.d /etc/audit/rules.d /opt/app/conf \
 && touch /var/log/audit/audit.log /var/log/secure /var/log/messages \
          /var/lib/mysql/ibdata1 /etc/audit/rules.d/audit.rules

# 模拟命令：让容器内的 systemctl/auditctl/mysql 等表现出真实语法，
# 但实际只回显，避免依赖完整 systemd/数据库。
COPY mock-bin/ /usr/local/sbin/
RUN chmod +x /usr/local/sbin/*

COPY banner.txt /etc/banner.txt
RUN echo 'cat /etc/banner.txt 2>/dev/null || true' >> /etc/bash.bashrc

# 入口与 sshd 完全沿用基础镜像的 /init（s6-overlay）
