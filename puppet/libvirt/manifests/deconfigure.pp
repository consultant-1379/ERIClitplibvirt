# Defining the Libvirt deconfigure
define libvirt::deconfigure (
            $instance_name,           # string
            $base_os = ''             # string
        ) {

  $inst_path = "/var/lib/libvirt/instances/${instance_name}"

  exec { "undefine_instance_${instance_name}":
    command => "litp_libvirt_adaptor.py ${instance_name} force-stop-undefine",
    path    => '/usr/bin:/opt/ericsson/nms/litp/lib/litpmnlibvirt',
    returns => [0, 2],
    onlyif => ["test -d ${inst_path}"],
  }

  file { "remove_instance_${instance_name}":
    ensure  => absent,
    path    => "${inst_path}",
    recurse => true,
    purge   => true,
    force   => true,
    require => Exec["undefine_instance_${instance_name}"],
  }

  if $base_os != 'rhel6' {
    file { "/usr/lib/systemd/system/${instance_name}.service":
      ensure  => absent,
    }
  } else {
    file { "/etc/init.d/${instance_name}":
      ensure => absent,
    }
  }
}
