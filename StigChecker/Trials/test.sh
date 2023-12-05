#!/bin/bash

configure_pam_pkcs11() {
  if grep -q "use_mappers = pwent" /etc/pam_pkcs11/pam_pkcs11.conf; then
    echo "The Config is already set"  
  else
    # If not found, add it to the configuration file
    if [ -f /etc/pam_pkcs11/pam_pkcs11.conf ]; then
      sed -i '/^use_mappers =/ s/$/ pwent/' /etc/pam_pkcs11/pam_pkcs11.conf
      echo "Added 'use_mappers = pwent' to /etc/pam_pkcs11/pam_pkcs11.conf"
    else
      # If the configuration file doesn't exist, copy the example
      if [ -f /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz ]; then
        zcat /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz > /etc/pam_pkcs11/pam_pkcs11.conf
        echo "Copied example configuration to /etc/pam_pkcs11/pam_pkcs11.conf"
      else
        echo "Error: Example configuration file not found."
      fi
    fi
  fi
}


main(){

  configure_pam_pkcs11


}
main
