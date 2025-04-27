# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "fbsd_13_0" do |fbsd_13_0|
    fbsd_13_0.vm.box = "freebsd/FreeBSD-13.0-RELEASE"
  end

  config.vm.define "fbsd_12_2" do |fbsd_12_2|
    fbsd_12_2.vm.box = "freebsd/FreeBSD-12.2-STABLE"
  end

  config.vm.synced_folder ".", "/vagrant", type: "rsync",
    rsync__auto: true

  config.vm.provision "shell", inline: <<-SHELL
    pkg bootstrap
    pkg install -y rust
  SHELL
end
