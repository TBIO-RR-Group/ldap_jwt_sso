NAME=ldap_jwt_sso
VERSION:=0.1
REGISTRY=<MY_DOCKER_REGISTRY_DOMAIN_AND_PORT>
LISTEN_PORT=8443
CERT_FILE=/path/to/cert/cert.crt
KEY_FILE=/path/to/key/cert.key
CONFIG_FILE=/path/to/config.txt
CAFILE_ARG=-v /path/to/adauthfile.pem:/etc/ssl/certs/adauth-na.pem
RUN_ARGS= --rm -p ${LISTEN_PORT}:${LISTEN_PORT} -v ${CERT_FILE}:/etc/ssl/certs/domain.crt -v ${KEY_FILE}:/etc/ssl/certs/domain.key -v ${CONFIG_FILE}:/perl_mods/config.txt
SHELL_EXTRA_ARGS=-v ${PWD}:${PWD} -w ${PWD}


build: 
	docker build --platform linux/amd64 -t ${REGISTRY}/${NAME}:${VERSION} \
                        -t ${NAME}:${VERSION} \
                        -f Dockerfile .

buildfresh: 
	docker build --platform linux/amd64 -t ${REGISTRY}/${NAME}:${VERSION} --no-cache \
                        -t ${NAME}:${VERSION} \
                        -f Dockerfile .

run:
	docker run -d ${CAFILE_ARG} ${RUN_ARGS} ${NAME}:${VERSION} /startup.sh ${LISTEN_PORT}

shell:
	docker run -it ${CAFILE_ARG} ${RUN_ARGS} ${SHELL_EXTRA_ARGS} --entrypoint /bin/bash ${NAME}:${VERSION}
