# jenkins-update-center-mirror
This tool creates a shallow copy of jenkins update center. This tool is inteded for audience that is not able to connect jenkins to internet, but would like use update center for installing plugins

## Security features
This tool has following security features (that are lacking from most/all other similar tools):

* Update center signature validation
* Plugin checksum validation
* Signing the local update center

## How to use in production
1. Create a certificate for your update center
2. Modify config.yml (define plugins that you want to include in your repo, certificates, url of site you will be hosting update center, etc.)
3. Run uc_update.py: python uc_update.py config.yml (you should schedule this in cron)
4. Setup a web site for update center
5. Provide certificate of your update center to jenkins by installing it using PEM format in jenkins_home/update-center-rootCAs
6. Change update site from jenkins configuration

## How to test on workstation (docker)
Run 'python uc_update.py config.yml' and 'docker-compose up'. Please notice that provided docker configuration is not intended for production!

## Updating the ca certificate
If you encounter problems with validating the certificate (not signature), check jenkins source code for updated root ca.

https://github.com/jenkinsci/jenkins/blob/master/war/src/main/webapp/WEB-INF/update-center-rootCAs/
