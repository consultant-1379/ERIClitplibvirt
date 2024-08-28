# Defining the Libvirt copy file
define libvirt::copy_file (
            $source_file_path,        # string
            $target_path,             # string
            $file_name,               # string
            $instance_name,           # string
            $latest_checksum = '',    # string
            $base_os = ''             # string
        ) {

  require libvirt

  Exec { path => [ '/bin/', '/sbin/' , '/usr/bin/', '/usr/sbin/' ] }

  if $base_os != 'rhel6' {
    file { "/usr/lib/systemd/system/${instance_name}.service":
      ensure  => file,
      mode    => '0644',
      content => template('libvirt/service_unit.erb')
    }
    if $puppet_master == True {
      exec { "systemctl_enable_${instance_name}_no_vcs":
        command => "systemctl enable ${instance_name}.service",
        unless => "test -L /etc/systemd/system/multi-user.target.wants/${instance_name}.service",
        require => File["/usr/lib/systemd/system/${instance_name}.service"]
      }
    }
  } else {
    $base_file='/opt/ericsson/nms/litp/'
    $adaptor_file='lib/litpmnlibvirt/litp_libvirt_adaptor.py'
    file { "/etc/init.d/${instance_name}":
      ensure  => file,
      mode    => '0755',
      content => "exec ${base_file}${adaptor_file} ${instance_name} \${@}"
    }
  }

  exec { "instances_parent_${instance_name}":
    command => 'mkdir -p /var/lib/libvirt/instances',
    unless  => 'test -d /var/lib/libvirt/instances',
  }

  # Target directory
  file { "/var/lib/libvirt/instances/${instance_name}":
    ensure  => directory,
    mode    => '0755',
    owner   => 'root',
    group   => 'root',
    require => Exec["instances_parent_${instance_name}"]
  }

  # Copy checksum file
  $source_checksum_file_path = "${source_file_path}.md5"
  $target_checksum_file_path = "${target_path}${file_name}_checksum.md5"
  $target_file_path = "${target_path}${file_name}"
  $checksum_file = "${target_file_path}.md5"
  $lock_file = $target_file_path
  $check_files_and_checksum_cmd = "test ! -f ${target_checksum_file_path} || \
                                   test ! -f ${target_file_path} || \
                                   test ! -f ${checksum_file} || ! diff \
                                    -w ${target_checksum_file_path} \
                                   ${checksum_file} || (test -n \
                                   '${latest_checksum}' && ! echo \
                                   ${latest_checksum} | diff -w \
                                   ${checksum_file} - )"

  # Copy image file and checksum
  $copy_checksum_cmd = "wget ${source_checksum_file_path} -O \
                        ${target_checksum_file_path} --no-check-certificate"
  $copy_image_cmd = "wget ${source_file_path} -O ${target_file_path} \
                     --no-check-certificate"
  $create_checksum_cmd = "md5sum ${target_file_path} | \
                          tr ' ' '\n' | \
                          head -n1 > ${checksum_file}"

  exec { "copy_image_${instance_name}":
    command => "flock -n ${lock_file} -c \"${copy_image_cmd} && \
                                           ${copy_checksum_cmd} && \
                                           ${create_checksum_cmd}\"",
    tries   => 2,
    onlyif  => [$check_files_and_checksum_cmd],
    require => Package['libvirt'],
    notify  => Exec["check_file_${instance_name}"],
    returns => [0, 1]
  }

  # Check files
  $check_checksum_cmd = "diff -w ${target_checksum_file_path} \
                         ${target_path}${file_name}.md5"
  exec { "check_file_${instance_name}":
    command => "flock -w 300 ${lock_file} -c \"${check_checksum_cmd}\"",
    unless  => $check_checksum_cmd,
    require => Exec["copy_image_${instance_name}"]
  }
}
