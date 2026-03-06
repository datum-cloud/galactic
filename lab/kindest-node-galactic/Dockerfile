FROM kindest/node:v1.34.0
RUN mkdir /galactic
COPY install.sh /galactic/
COPY mqtt.k8s.yml /galactic/
COPY router.k8s.yml /galactic/
COPY agent.k8s.yml /galactic/
RUN chmod +x /galactic/install.sh
