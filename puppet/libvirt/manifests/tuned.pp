#
# install and configure "tuned"
#
class libvirt::tuned{

  $profile = 'virtual-host'

  package { 'tuned':
    ensure  => 'installed',
  }

  service { 'tuned':
    ensure  => 'running',
    enable  => true,
    require=> Exec['enable_tuned_profile'],
  }

  #change the tuned profile to virtual-host
  exec {'enable_tuned_profile':
    command => "tuned-adm profile ${profile}",
    unless  => "tuned-adm active | grep -q -e 'Current active profile: ${profile}\$'",
    require => Package['tuned'],
    path    => ['/usr/sbin', '/usr/bin', '/bin'],
  }
}
