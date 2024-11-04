# Install from https://install.bare.sh

# download raw user content from github
sudo curl -s https://raw.githubusercontent.com/matthewlarkin/bare.sh/root/bare.sh -o /usr/local/bin/bare.sh && sudo chmod +x /usr/local/bin/bare.sh

# test bare.sh random number (should return a number)
random_number=$(bare.sh random number)

# if random number is not a number, then remove the file
if ! [[ $random_number =~ ^[0-9]+$ ]]; then
  sudo rm /usr/local/bin/bare.sh
  echo "Failed to install bare.sh"
  exit 1
fi

# if random number is a number, then install was successful
echo ""
echo "  - - - "
echo ""
echo "  ✅ Successfully installed bare.sh"
echo "  ✅ You can now run 'bare.sh' from the command line."
echo ""
echo "  ☑️  Visit samples.bare.sh for sample usage."
echo "  ☑️  If future updates are available, you can run 'bare.sh --upgrade' to upgrade to the latest version."
echo ""
echo "  - - - "
echo ""
