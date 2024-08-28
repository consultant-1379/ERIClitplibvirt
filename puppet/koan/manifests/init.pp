#
# basic libvirt and koan config
#
class koan {
  $packages = [ 'koan', 'libvirt', 'dbus' ]

  package { $packages:
    ensure  => installed,
  }

  $services = [ 'messagebus', 'libvirtd' ]

  service { $services :
    ensure  => running,
    enable  => true,
    require => [Package['dbus', 'libvirt'], File[libvirt-guests]]
  }

  file { 'libvirt-guests':
    ensure => file,
    path   => '/etc/rc.d/init.d/libvirt-guests',
    source => 'puppet:///modules/koan/libvirt-guests',
    mode   => '0755',
    owner  => 'root',
    group  => 'root'
  }

  exec { 'disablevirbr0':
        path    => '/bin:/usr/bin',
        command => 'virsh net-destroy default;virsh net-undefine default',
        onlyif  => 'virsh net-list --all | grep -wq default',
        require => Package['libvirt'],
    }

}

