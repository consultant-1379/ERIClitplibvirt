#
# basic libvirt config
#
class libvirt {
  include libvirt::tuned

  $packages = [ 'libvirt', 'dbus' ]

  package { $packages:
    ensure  => installed,
  }

  $services = [ 'messagebus', 'libvirtd' ]

  $default_nets = [ '/var/lib/libvirt/network/default.xml',
                  '/etc/libvirt/qemu/networks/autostart/default.xml',
                  '/etc/libvirt/qemu/networks/default.xml' ]

  file { $default_nets:
    ensure  => 'absent',
    require => Package['libvirt']
  }

  exec { 'disablevirbr0':
    path    => '/bin:/usr/bin',
    command => 'virsh net-destroy default;virsh net-undefine default',
    onlyif  => 'virsh net-list --all | grep -wq default',
    require => [Package['libvirt'], File[$default_nets]]
  }

  service { $services:
    ensure  => 'running',
    enable  => true,
    require => [Package['dbus', 'libvirt'], File[$default_nets]]
  }

  if $::operatingsystemmajrelease == '6' {
    file_line { 'libvirt_guests_onshutdown_shutdown':
      ensure  => present,
      path    => '/etc/rc.d/init.d/libvirt-guests',
      match   => '^ON_SHUTDOWN=.',
      line    => 'ON_SHUTDOWN=shutdown',
      require => Package['libvirt']
    }

    # Add a file for libvirt-guests and libvirtd to override the shutdown
    # priority and run the override command

    file { '/etc/chkconfig.d/libvirtd':
      ensure  => file,
      mode    => '0755',
      content => template('libvirt/libvirtd.erb'),
      require => Package['libvirt']
    }

    exec { 'libvirtd_override_config':
      command     => '/sbin/chkconfig libvirtd reset',
      refreshonly => true,
      subscribe   => File['/etc/chkconfig.d/libvirtd'],
      before      => Exec['libvirtguests_override_config']
    }

    file { '/etc/chkconfig.d/libvirt-guests':
      ensure  => file,
      mode    => '0755',
      content => template('libvirt/libvirt-guests.erb'),
      require => Package['libvirt']
    }

    exec { 'libvirtguests_override_config':
      command     => '/sbin/chkconfig libvirt-guests reset',
      subscribe   => File['/etc/chkconfig.d/libvirt-guests'],
      refreshonly => true
    }
  }

  augeas { 'libvirtd.conf':
    context => '/files/etc/libvirt/libvirtd.conf',
    changes => ['set max_clients 55',
                'set max_workers 50'],
    notify  => Service['libvirtd'],
    require => Package['libvirt'],
  }

  file { 'vm_utils':
    ensure  => file,
    require => File['litp_libvirt_dir'],
    path    => '/usr/share/litp_libvirt/vm_utils',
    mode    => '0755',
    source  => 'puppet:///modules/libvirt/vm_utils',
  }

  file { 'litp_libvirt_dir':
    ensure => directory,
    path   => '/usr/share/litp_libvirt',
    mode   => '0755',
    owner  => 'root',
    group  => 'root',
  }
}
