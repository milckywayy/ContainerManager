FROM archlinux:latest

RUN pacman -Syu --noconfirm

RUN pacman -S --noconfirm openssh sudo

RUN useradd -m -s /bin/bash student \
    && echo "student:12345678" | chpasswd

RUN ssh-keygen -A
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config

EXPOSE 22

COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

WORKDIR /home/student

CMD ["/usr/local/bin/start.sh"]
