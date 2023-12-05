#!/bin/bash
##################################################################################
#                                                                                #
# IS 580_02 Kali Linux and Bash                                                  #
# DJ Hovermale                                                                   #
#                                                                                #
#                                                                                #
# James Thrasher                                                                 #
#                                                                                #
# Fall 2023                                                                      #
#                                                                                #
# STIG Automation Final Project in Bash                                          #
#                                                                                #
# Functions and resources include Github, and Defense Information Systems Agency #
#                                                                                @
#                                                                                #
##################################################################################


###################
# Category 2      #
###################


V-238291() {

  echo "Executing function: V-238291 - Checking PAM file "
  echo " "
  if grep -q "use_mappers = pwent" /etc/pam_pkcs11/pam_pkcs11.conf; then
    echo "The Config is already set"
  else
    # If not found, add it to the configuration file
    if [ -f /etc/pam_pkcs11/pam_pkcs11.conf ]; then
      sed -i '/^use_mappers =/ s/$/ pwent/' /etc/pam_pkcs11/pam_pkcs11.conf
      echo "Added 'use_mappers = pwent' to /etc/pam_pkcs11/pam_pkcs11.conf"
      echo " "
    else
      # If the configuration file doesn't exist, copy the example
      if [ -f /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz ]; then
        zcat /usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz > /etc/pam_pkcs11/pam_pkcs11.conf
        echo "Copied example configuration to /etc/pam_pkcs11/pam_pkcs11.conf"
        echo " "
      else
        echo "Error: Example configuration file not found."
        echo " "
      fi
    fi
  fi
}

V-238204() {
  echo "Executing function: V-238204 - Checking and configuring GRUB for enhanced security."
  echo " "

  if [ ! -f /boot/grub/grub.cfg ]; then
    echo "The /boot/grub/grub.cfg file does not exist."
    echo " "
    return 1
  fi

  makepasshash=$(grub-mkpasswd-pbkdf2)
  config=$(grep -i "password_pbkdf2" /boot/grub/grub.cfg)

  if [[ "$config" == *password_pbkdf2* ]]; then
    echo "The root password entry begins with 'password_pbkdf2'. No findings."
    echo " "
  else
    echo "Root password entry does not begin with 'password_pbkdf2'. This is a finding."
    echo " "

    sed -i '/^set superusers/d' /etc/grub.d/40_custom
    echo "set superusers=\"root\"" >> /etc/grub.d/40_custom
    echo " "
    echo "password_pbkdf2 root $makepasshash" >> /etc/grub.d/40_custom

    update-grub
  fi
}

V-238256() {
  
  echo "Executing function: V-238256 - Checking if Ubuntu system generates audit records for ssh-agent usage."
  echo " "

  if [ ! -f /etc/audit/rules.d/stig.rules ]; then
    echo "Stig rules do not exist"
    echo " " 
    return 1
  fi

  audit=$(auditctl -l | grep '/usr/bin/ssh-agent')
  config="-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-ssh"

  if [ "$audit" == "$config" ]; then

    echo "The Ubuntu system generates an audit record upon attempts to use the ssh-agent"
    echo " "

  else

    echo "The Ubuntu system does not generate an audit record upon attempts to use the ssh-agent"
    echo " "

  fi
}

V-238208() {

  echo "Executing function: V-238208 - Checking and fixing NOPASSWD and !authenticate in sudoers configuration."

  echo " "
  verification=$(sudo egrep -i '(nopasswd|authenticate)' /etc/sudoers /etc/sudoers.d/*)
  
  if [ -n "$verification" ]; then
    read -p "Do you want to fix this vulnerability? (y/n): " answer
    echo " "

    if [ "$answer" == "y" ]; then
      # Use double quotes to prevent issues with special characters in file paths
      sudo sed -i -r '/(NOPASSWD|!authenticate)/d' /etc/sudoers /etc/sudoers.d/*
      echo "Occurrences removed successfully."
      echo " "
    else
      echo "No changes made."
      echo " "
    fi
  else
    echo "No occurrences of NOPASSWD or !authenticate found. Rule satisfied."
    echo " "
  fi
}

###################
# Category 1      #
###################

V-238201() {



  #"Checking that the Mappers rule is set to pwent "  
  echo "Executing function: V-238201 - Checking and updating Mappers rule in PAM configuration."
  echo " "



  example_config="/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz"
  config_file="/etc/pam_pkcs11/pam_pkcs11.conf"
  desired_setting="use_mappers = pwent"

  if [ ! -f "$config_file" ]; then
    echo "Mappers Rule does not exist"
    echo " "
    return 1
  fi

  # Check if use_mappers is set to pwent
  if grep -q "^use_mappers[[:space:]]*=[[:space:]]*pwent" "$config_file"; then
    echo "Configuration is already set to use_mappers = pwent"
    echo " "
  else
    # Check if use_mappers is present
    if grep -q "^use_mappers" "$config_file"; then
      # Prompt before making changes
      read -p "The configuration needs to be updated. Do you want to proceed? (y/n): " choice
      echo " "
      if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        # Add pwent to the existing list or set it if not present
        sed -i '/^use_mappers/s/$/, pwent/' "$config_file"
        echo "Added pwent to use_mappers in $config_file"
        echo " "
      else
        echo "No changes made to the configuration."
        echo " "
      fi
    else
      # Prompt before making changes
      read -p "The configuration needs to be updated. Do you want to proceed? (y/n): " choice
      echo " "
      if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        # Add use_mappers = pwent if not present
        echo "$desired_setting" >> "$config_file"
        echo "Set use_mappers to pwent in $config_file"
        echo " "
      else
        echo "No changes made to the configuration."
        echo " "
      fi
    fi
  fi
}


V-251504() {
  echo "Checking for the 'nullok' option in /etc/pam.d/common-password..."
  echo " "
  nullok=$(grep -q nullok /etc/pam.d/common-password)
  if $nullok; then
    read -p "Do you want to remove the 'nullok' option? (y/n): " answer
    echo " "
    if [ "$answer" == "y" ]; then
      # remove all occurrences of nullok
      sudo sed -i '/nullok/d' /etc/pam.d/common-password
      echo "The 'nullok' option has been removed successfully."
      echo " "
    else
      echo "No changes made."
    fi
  else
    echo "No occurrences of 'nullok' found is compliant. "
  fi
}

V-251503() {

  echo "Executing function: V-251504 - Checking and removing 'nullok' option in /etc/pam.d/common-password..."
  
  echo " "

  echo "Checking for accounts with blank passwords in /etc/shadow..."

  blank_passwords=$(sudo awk -F: '!$2 {print $1}' /etc/shadow)

  if [ -n "$blank_passwords" ]; then
    echo "Found accounts with blank passwords: $blank_passwords"
    echo " "
    read -p "Do you want to lock these accounts and set new passwords? (y/n): " answer

    if [ "$answer" == "y" ]; then
      for user in $blank_passwords; do
        read -s -p "Enter a new password for $user: " new_password
        echo " "
        echo
        sudo passwd $user <<<"$new_password"
        sudo passwd -l $user
      done
      echo "Accounts locked and passwords reset successfully."
      echo " "
    else
      echo "No changes made."
      echo " "
    fi
  else
    echo "No accounts with blank passwords found. Rule satisfied."
  fi
}

V-238363() {

  echo "Executing function: V-238363 - Checking if the system is configured to run in FIPS mode..."

  echo " "

  echo "Checking if the system is configured to run in FIPS mode..."

  fips_enabled=$(grep -i 1 /proc/sys/crypto/fips_enabled)

  if [ "$fips_enabled" == "1" ]; then
    echo "The system is configured to run in FIPS mode. Rule satisfied."
    echo " "
  else
    read -p "The system is not configured to run in FIPS mode. Do you want to configure it? (y/n): " answer
    echo " "
    if [ "$answer" == "y" ]; then
      echo "Configuring the system to run in FIPS mode..."
      echo " "
      # Add 'fips=1' to the GRUB configuration
      sudo sed -i '/GRUB_CMDLINE_LINUX/s/"$/ fips=1"/' /etc/default/grub

      # Update GRUB
      sudo update-grub

    else
      echo "No changes made."
    fi
  fi
}


V-252704(){
 echo "Executing function: V-252704 - Checking if the system has wireless interfaces enabled and disabling..."

  # Check if any wireless interfaces are configured
  wireless_interfaces=$(ls -L -d /sys/class/net/*/wireless | xargs dirname | xargs basename)

  if [ -n "$wireless_interfaces" ]; then
    echo "Wireless interfaces found. Disabling and documenting..."
    
    for interface in $wireless_interfaces; do
      # Disable the wireless network interface
      sudo ifdown "$interface"

      # Find the module for the wireless interface
      module=$(basename $(readlink -f /sys/class/net/$interface/device/driver))

      # Create a file in "/etc/modprobe.d" to disable the module
      echo "install $module /bin/true" | sudo tee -a /etc/modprobe.d/disable_wireless.conf

      # Remove the module
      sudo modprobe -r "$module"
    done

    echo "Wireless interfaces have been disabled and documented."
  else
    echo "No wireless interfaces found. This check passed."
  fi
}









}





#!/bin/bash

help_function() {
  echo "Usage: $0 [category]"
  echo "Options:"
  echo "  -h, --help   Display this help message"
  echo "  category     Specify the category to execute (1, 2, 3, or 4)"
  echo "               If not provided, the script will prompt for the category."
}

main() {
  # Check if a command-line argument is provided
  if [ "$#" -eq 1 ]; then
    case $1 in
      -h|--help)
        help_function
        exit 0
        ;;
      [1-4])
        category=$1
        ;;
      *)
        echo "Invalid category"
        help_function
        exit 1
        ;;
    esac
  else
    # Prompt user to choose a category
    echo "Choose a category to execute:"
    echo "1. Category 1 "
    echo "2. Category 2 "
    echo "3. All Available"
    read -p "Enter the number of the category: " category
  fi

  # Execute functions based on the chosen category
  case $category in
    1)
      V-238201
      echo "#########################################"
      echo "                                         "
      V-238208
      echo "#########################################"
      echo "                                         "
      V-238363
      echo "#########################################"
      echo "                                         "
      V-251503
      echo "#########################################"
      echo "                                         "
      V-252704
      ;;
    2)
      V-238204
      echo "#########################################"
      echo "                                         "
      V-238291
      echo "#########################################"
      echo "                                         "
      V-238256
      ;;
    3)
      V-238201
      echo "#########################################"
      echo "                                         "
      V-238208
      echo "#########################################"
      echo "                                         "
      V-238363
      echo "#########################################"
      echo "                                         "
      V-251503
      echo "#########################################"
      echo "                                         "
      V-238204
      echo "#########################################"
      echo "                                         "
      V-238291
      echo "#########################################"
      echo "                                         "
      V-238256
      echo "#########################################"
      echo "                                         "
      V-252704

      ;;
    4)
      # Add code for category 4 here
      ;;
    *)
      echo "Invalid category"
      help_function
      exit 1
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

# Check if a command-line argument is provided
if [ "$#" -eq 1 ]; then
  # Call the main function with the provided argument
  main "$1"
else
  # Call the main function without command-line argument
  main
fi

