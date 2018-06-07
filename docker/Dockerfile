FROM modusbox-wm-docker.jfrog.io/wavemoney/mule-ee-docker:3.9.0-717380b-18
LABEL maintainer="David Fry <david.fry@modusbox.com>"

ENV MULE_TMP_APP_DIR=/opt/mule/tempapps MULE_CONTAINER_AUTO_DEPLOY=true TZ=Asia/Yangon

RUN mkdir $MULE_TMP_APP_DIR && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

COPY domains/* /opt/mule/domains/
COPY apps/* $MULE_TMP_APP_DIR/
COPY wrapper.conf /opt/mule/conf/wrapper.conf

