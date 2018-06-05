FROM modusbox-wm-docker.jfrog.io/wavemoney/mule-ee-docker:3.9.0-97685c2-9
LABEL maintainer="David Fry <david.fry@modusbox.com>"

ENV MULE_TMP_APP_DIR=/opt/mule/tempapps MULE_CONTAINER_AUTO_DEPLOY=true

RUN mkdir $MULE_TMP_APP_DIR

COPY domains/* /opt/mule/domains/
COPY apps/* $MULE_TMP_APP_DIR/
COPY wrapper.conf /opt/mule/conf/wrapper.conf

