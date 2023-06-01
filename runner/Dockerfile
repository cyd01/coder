FROM	ubuntu:latest

USER 	root

ENV     DEBIAN_FRONTEND=noninteractive
RUN	    sed -i -e 's/^APT/# APT/' -e 's/^DPkg/# DPkg/' /etc/apt/apt.conf.d/docker-clean

RUN	    ln -f -s /usr/share/zoneinfo/Europe/Paris /etc/localtime

RUN     \
	    apt update                                                                                         \
		&& apt install -y openssh-server                                                                   \
		&& echo "PermitRootLogin yes" >> /etc/ssh/sshd_config                                              \
		&& sed -i 's/^[#]*[ ]*PasswordAuthentication .*$/PasswordAuthentication yes/' /etc/ssh/sshd_config \
		&& mkdir /run/sshd && chmod 755 /run/sshd

COPY    keys/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key
COPY    keys/ssh_host_dsa_key.pub /etc/ssh/ssh_host_dsa_key.pub
COPY    keys/ssh_host_ecdsa_key /etc/ssh/ssh_host_ecdsa_key
COPY    keys/ssh_host_ecdsa_key.pub /etc/ssh/ssh_host_ecdsa_key.pub
COPY    keys/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key
COPY    keys/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_ed25519_key.pub
COPY    keys/ssh_host_rsa_key /etc/ssh/ssh_host_rsa_key
COPY    keys/ssh_host_rsa_key.pub /etc/ssh/ssh_host_rsa_key.pub

RUN    chmod 600 /etc/ssh/ssh_host*_key*

RUN     \
	    apt-get install -y ca-certificates curl docker.io docker-compose iputils-ping jq make mlocate net-tools nmon openssl perl sudo tmux unzip vim wget

RUN 	echo "root:root01" | chpasswd

RUN     \
        curl -sSkLO https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl \
        && chmod +x ./kubectl \
        && mv ./kubectl /usr/local/bin/kubectl \
        && kubectl version --client >&2

RUN     \
	    useradd -m -p `perl -e "print crypt('user01', 'sa');"` -s /bin/bash user \
		&& usermod -aG sudo user
RUN     \
	    useradd -m -p `perl -e "print crypt('ubuntu01', 'sa');"` -s /bin/bash ubuntu \
		&& usermod -aG sudo ubuntu

RUN     printf 'alias ll='\''ls -lart'\''export PS1="\u@\h:\w> "' > /home/user/.profile
RUN 	printf 'if [ -f ~/.profile ] ; then . ~/.profile ; fi' > /home/user/.bash_profile
RUN  	printf 'export PS1="\u@\h:\w> "' > /home/user/.bashrc


COPY    id_rsa.pub /etc/id_rsa.pub
RUN     \
        mkdir -p /home/user/.ssh \
		&& cat /etc/id_rsa.pub >> /home/user/.ssh/authorized_keys \
	    && chown -R user:user /home/user && chmod 700 /home/user/.ssh
RUN     \
        mkdir -p /home/ubuntu/.ssh \
		&& cat /etc/id_rsa.pub >> /home/ubuntu/.ssh/authorized_keys \
	    && chown -R ubuntu:ubuntu /home/ubuntu && chmod 700 /home/ubuntu/.ssh

RUN 	echo 'Prepare authenticator' && apt-get install -y libpam-google-authenticator && sed -i 's/^[#]*[ ]*ChallengeResponseAuthentication .*$/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config && echo 'auth required pam_google_authenticator.so nullok' >> /etc/pam.d/common-session && echo 'Authenticator enabled'

COPY 	Dockerfile /etc/Dockerfile
COPY 	entrypoint.sh /entrypoint.sh
RUN 	chmod +x /entrypoint.sh ; touch /etc/Dockerfile

EXPOSE 	22

WORKDIR	/root

ENTRYPOINT [ "/entrypoint.sh" ]

