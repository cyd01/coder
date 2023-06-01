#!/usr/bin/env bash

# generate host keys if not present
echo "Generating ssh server keys..."
ssh-keygen -A

update-ca-certificates &

# print authenticator informationq
echo "Print 2FA authentication informations"
#printf 'y\ny\ny\ny\ny\n'|google-authenticator
#echo
printf '5J4AN4PTRRDNLEMDFZCNYSU27I\n" RATE_LIMIT 3 30 1606859684\n" WINDOW_SIZE 17\n" DISALLOW_REUSE 53561989\n" TOTP_AUTH\n60646780\n34971365\n94741338\n24375590\n61181726' > /root/.google_authenticator && chmod 400 /root/.google_authenticator
cat /root/.google_authenticator
echo

test -z "${USER_NAME}" || id ${USER_NAME} > /dev/null 2>&1 || {
  export USER_PASS=${USER_PASS:-${USER_NAME}01}
  export USER_UID=${USER_UID:-6000}
  export USER_GID=${USER_GID:-${USER_UID}}
  getent group ${USER_NAME} || { echo "Creating group ${USER_NAME} with GID ${USER_GID}" ; groupadd --gid ${USER_GID} ${USER_NAME} ; }
  echo "Creating user ${USER_NAME} with UID ${USER_UID}"
  useradd --create-home --uid "${USER_UID:-1000}" --gid ${USER_NAME} --groups sudo --shell ${SHELL:-/bin/bash} ${USER_NAME}
}
test -z "${USER_PASS}" || {
  echo "Change password for user ${USER_NAME:-ubuntu} to ${USER_PASS}"
  echo "${USER_NAME:-ubuntu}:${USER_PASS}" | chpasswd
}
test ! -S /var/run/docker.sock || {
  DOCKER_SOCK_GROUP_ID=$(stat -c '%g' /var/run/docker.sock)
  getent group ${DOCKER_SOCK_GROUP_ID} > /dev/null || { echo "Create group docker-host with ID ${DOCKER_SOCK_GROUP_ID}" ; groupadd --gid ${DOCKER_SOCK_GROUP_ID} docker-host ; }
  DOCKER_SOCK_GROUP_NAME=$(getent group ${DOCKER_SOCK_GROUP_ID} | awk -F: '{print $1;}')
  echo "Add user ${USER_NAME:-ubuntu} to group ${DOCKER_SOCK_GROUP_NAME}"
  usermod --append --groups ${DOCKER_SOCK_GROUP_NAME} ${USER_NAME:-ubuntu}
}
test -z "${USER_NAME}" || {
  echo "${USER_NAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/10-${USER_NAME} && chmod 400 /etc/sudoers.d/10-${USER_NAME}
  mkdir -p /home/${USER_NAME}/.kube
  touch /home/${USER_NAME}/.sudo_as_admin_successful
  chown -R ${USER_NAME}:${USER_NAME} /home/${USER_NAME}
}
unset USER_NAME USER_PASS PASS USER_UID USER_GID

test -z $DOCKER_HOST || echo "DOCKER_HOST=$DOCKER_HOST" >> /etc/environment 

updatedb &

bash -c 'exec 3<> /dev/tcp/git/3000'
while [ $? -ne 0 ] ; do
  sleep 1
  bash -c 'exec 3<> /dev/tcp/git/3000'
done

curl -X POST 'http://git:3000/' \
  -H 'User-Agent: cURL' \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
  -H 'Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3' \
  -H 'Accept-Encoding: gzip, deflate, br' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Origin: null' \
  -H 'Upgrade-Insecure-Requests: 1' \
  -H 'Sec-Fetch-Dest: document' \
  -H 'Sec-Fetch-Mode: navigate' \
  -H 'Sec-Fetch-Site: same-origin' \
  -H 'Sec-Fetch-User: ?1' \
  -H 'Connection: keep-alive' \
  --data-raw 'db_type=sqlite3&db_host=localhost%3A3306&db_user=root&db_passwd=&db_name=gitea&ssl_mode=disable&db_schema=&db_path=%2Fdata%2Fgitea%2Fgitea.db&app_name=Gitea%3A+Git+with+a+cup+of+tea&repo_root_path=%2Fdata%2Fgit%2Frepositories&lfs_root_path=%2Fdata%2Fgit%2Flfs&run_user=git&domain=localhost&ssh_port=22&http_port=3000&app_url=http%3A%2F%2Flocalhost%3A8080%2Fgit%2F&log_root_path=%2Fdata%2Fgitea%2Flog&smtp_addr=&smtp_port=&smtp_from=&smtp_user=&smtp_passwd=&enable_federated_avatar=on&enable_open_id_sign_in=on&enable_open_id_sign_up=on&default_allow_create_organization=on&default_enable_timetracking=on&no_reply_address=noreply.localhost&password_algorithm=pbkdf2&admin_name=administrator&admin_email=nobody%40nowhere.local&admin_passwd=admin001&admin_confirm_passwd=admin001'

if [ $# -ne 0 ] ; then 
  echo "Start ssh daemon in background"
  # do not detach (-D), log to stderr (-e), passthrough other arguments
  exec /usr/sbin/sshd -D -e &

  /bin/bash
  exit $?
else
  echo "Start ssh daemon in foreground"
  # do not detach (-D), log to stderr (-e), passthrough other arguments
  exec /usr/sbin/sshd -D -e "$@"
fi


