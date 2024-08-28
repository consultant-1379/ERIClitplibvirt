#
# create libvirt vm using koan
#
define koan::config($cobbler_server, $cobbler_system, $bridge, $system_name,
                    $path) {

  include koan

  if $::hostname == $::servername {
    exec { "set-${title}":
        require => [Package['koan'], Service['libvirtd']],
        command => "koan --server ${cobbler_server} \
                   --system=${cobbler_system} \
                   --virt --virt-bridge=${bridge} \
                   --virt-name=${system_name} \
                   --virt-path=${path} --virt-auto-boot \
                   --nogfx --vm-poll --virt-type=qemu \
                   --qemu-disk-type=ide &",
        path    => '/usr/bin:/bin',
        onlyif  => ["cobbler system list | grep -q ${cobbler_system}",
                    "test! -f ${path}/${system_name}-*",
                    "/sbin/ifconfig | grep ${bridge}"],
        timeout => 60,
    }
  }else{
    exec { "set-${title}":
        require => [Package['koan'], Service['libvirtd']],
        command => "koan --server ${cobbler_server} \
                   --system=${cobbler_system} --virt \
                   --virt-bridge=${bridge} \
                   --virt-name=${system_name} \
                   --virt-path=${path} --virt-auto-boot \
                   --nogfx --vm-poll --virt-type=qemu \
                   --qemu-disk-type=ide &",
        path    => '/usr/bin:/bin',
        onlyif  => ["test ! -f ${path}/${system_name}-*",
                    "/sbin/ifconfig | grep ${bridge}" ],
        timeout => 60,
    }
  }
}
