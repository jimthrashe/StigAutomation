#!/bin/bash








V-238291()  {
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












V-238204() {
  grub_cfg="/boot/grub/grub.cfg"

  if [ ! -f "$grub_cfg" ]; then
    echo "The $grub_cfg file does not exist."
    return 1
  fi

  makepasshash=$(grub-mkpasswd-pbkdf2)
  config=$(grep -i "password_pbkdf2" "$grub_cfg")

  if [[ "$config" == *password_pbkdf2* ]]; then
    echo "The root password entry begins with 'password_pbkdf2'. No findings."
  else
    echo "Root password entry does not begin with 'password_pbkdf2'. This is a finding."

    sed -i '/^set superusers/d' /etc/grub.d/40_custom
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo "password_pbkdf2 root $makepasshash" >> /etc/grub.d/40_custom

    # Make sure to update GRUB with the changes
    update-grub
  fi
}

V-238256(){
  
  if [ ! -f /etc/audit/rules.d/stig.rules]; then
    echo "Stig rules do not exist"
    return 1
  fi

  
  audit=$(auditctl -l | grep '/usr/bin/ssh-agent')
  confg="-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-ssh"
   
  
  if [["$audit" == "$cofnig"]]; then 
    
    echo "The Ubuntu system generates an audit record upon attempts to use the ssh-agent"

  else

    echo "The Ubuntu system does not generate an audit record upon attempts to use the ssh-agent"

  fi
}


V-238208() {
  
  verification=$(sudo egrep -i '(NOPASSWD|authenticate)' /etc/sudoers /etc/sudoers.d/*)

  if [[ -n "$verification" ]]; then
    read -p "Do you want to fix this vulnerability? (y/n): " answer

    if [ "$answer" == "y" ]; then
      #Use double quotes to prevent issues with special characters in file paths
      sudo sed -i -r '/(NOPASSWD|!authenticate)/d' /etc/sudoers /etc/sudoers.d/*
      echo "Occurrences removed successfully."
    else
      echo "No changes made."
    fi
    
  else
    echo "No occurrences of NOPASSWD or !authenticate found. Rule satisfied."
  fi
}



###################
#Cat 1            #
###################


V-238201() {
  echo "Checking that the Mappers rule is set to pwent "
  example_config="/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz"
  config_file="/etc/pam_pkcs11/pam_pkcs11.conf"
  desired_setting="use_mappers = pwent"

  if [ ! -f "$config_file" ]; then
    echo "Mappers Rule does not exist"
    return 1
  fi
  
  # Check if use_mappers is set to pwent
  if grep -q "^use_mappers[[:space:]]*=[[:space:]]*pwent" "$config_file"; then
    echo "Configuration is already set to use_mappers = pwent"
  else
    # Check if use_mappers is present
    if grep -q "^use_mappers" "$config_file"; then
      # Prompt before making changes
      read -p "The configuration needs to be updated. Do you want to proceed? (y/n): " choice
      if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        # Add pwent to the existing list or set it if not present
        sed -i '/^use_mappers/s/$/, pwent/' "$config_file"
        echo "Added pwent to use_mappers in $config_file"
      else
        echo "No changes made to the configuration."
      fi
    else
      # Prompt before making changes
      read -p "The configuration needs to be updated. Do you want to proceed? (y/n): " choice
      if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        # Add use_mappers = pwent if not present
        echo "$desired_setting" >> "$config_file"
        echo "Set use_mappers to pwent in $config_file"
      else
        echo "No changes made to the configuration."
      fi
    fi
  fi
  # Configuration file doesn't exist
  # check and see if example exists
  if [ ! -f "$config_file" ] && [ -f "$example_config" ]; then
    # Prompt before copying the example config
    read -p "Configuration file not found. Do you want to copy the example config? (y/n): " choice
    if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
      cp "$example_config" "$config_file"
      echo "Example config copied to $config_file. Please modify accordingly."
    else
      echo "No changes made. Please create the configuration file manually."
    fi
  elif [ ! -f "$example_config" ]; then
    echo "Example configuration file not found. Please check your installation and configure manually."
  fi
}
V-251504() {
    echo "Checking for the 'nullok' option in /etc/pam.d/common-password..."
    nullok=$(grep -q nullok /etc/pam.d/common-password)
    if $nullok; then
        read -p "Do you want to remove the 'nullok' option? (y/n): " answer
        if [ "$answer" == "y" ]; then
            #remove all occurences of nullok
            sudo sed -i '/nullok/d' /etc/pam.d/common-password
            echo "The 'nullok' option has been removed successfully."
        else
            echo "No changes made."
        fi
    else
        echo "No occurrences of 'nullok' found is compliant. "
    fi
}

V-251503() {
    echo "Checking for accounts with blank passwords in /etc/shadow..."

    blank_passwords=$(sudo awk -F: '!$2 {print $1}' /etc/shadow)

    if [ -n "$blank_passwords" ]; then
        echo "Found accounts with blank passwords: $blank_passwords"
        read -p "Do you want to lock these accounts and set new passwords? (y/n): " answer

        if [ "$answer" == "y" ]; then
            for user in $blank_passwords; do
                read -s -p "Enter a new password for $user: " new_password
                echo
                sudo passwd $user <<< "$new_password"
                sudo passwd -l $user
            done
            echo "Accounts locked and passwords reset successfully."
        else
            echo "No changes made."
        fi
    else
        echo "No accounts with blank passwords found. Rule satisfied."
    fi
}




V-238363() {

    echo "Checking if the system is configured to run in FIPS mode..."

    fips_enabled=$(grep -i 1 /proc/sys/crypto/fips_enabled)

    if [ "$fips_enabled" == "1" ]; then
        echo "The system is configured to run in FIPS mode. Rule satisfied."
    else
        read -p "The system is not configured to run in FIPS mode. Do you want to configure it? (y/n): " answer

        if [ "${answer,,}" == "y" ]; then
            echo "Configuring the system to run in FIPS mode..."
            
            # Add 'fips=1' to the GRUB configuration
            sudo sed -i '/GRUB_CMDLINE_LINUX/s/"$/ fips=1"/' /etc/default/grub
            
            # Update GRUB
            sudo update-grub
           
        else
            echo "No changes made."
        fi
    fi
}
main() {

  # Prompt user to choose a category
  echo "Choose a category to execute:"
  echo "1. Category 1 "
  echo "2. Category 2 "
  echo "3. All Available"
  read -p "Enter the number of the category: " category

  # Execute functions based on the chosen category
  case $category in
    1)
      V-238201
      V-238208
      V-238363
      V-251503
      ;;
    2)
      V-238204
      V-238291
      V-238256
      ;;
    3)
      V-238201
      V-238208
      V-238363
      V-251503

      V-238204
      V-238291
      V-238256
      ;;

    *)
      echo "Invalid category"
      ;;
  esac

 # Prompt for rebooting
  read -p "Do you want to reboot now? (y/n): " reboot_answer
            
  if [ "$reboot_answer" == "y" ]; then
  sudo reboot
  else
   echo "Complete."
  fi
}

# Call the main function
main

