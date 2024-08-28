#
# removes a libvirt vm from libvirt given the vm system_name and vm image path
#
define koan::remove($system_name, $path) {

    # virsh destory vm
    exec { "destory-vm-${title}":
        command => "virsh destory ${system_name}",
        path    => '/usr/bin:/bin',
        onlyif  => ["virsh desc ${system_name}"],
    }

    # virsh undefine vm
    exec { "undefine-vm-${title}":
        require => Exec["destroy-vm-${title}"],
        command => "virsh undefine ${system_name}",
        path    => '/usr/bin:/bin',
        onlyif  => ["virsh desc ${system_name}"],
    }

    # delete vm image file
    exec { "delete-vm-file-${title}":
        require => Exec["undefine-vm-${title}"],
        command => "rm -f ${path}/${system_name}-*",
        path    => '/usr/bin:/bin',
        onlyif  => ["test -f ${path}/${system_name}-*"],
    }

}
