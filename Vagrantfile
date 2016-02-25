# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

  config.vm.box = "ubuntu/trusty64"
  config.vm.network :private_network, ip: "10.0.2.30"
  config.vm.network :private_network, ip: "10.0.2.40"
  config.vm.network :private_network, ip: "10.0.2.100"

  # requires working internet connection
  config.vm.box_check_update = false
end
