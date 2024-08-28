
class task_ms1__koan_3a_3aconfig___56_4d1(){
    koan::config { "VM1":
        bridge => "br0",
        cobbler_server => "10.10.10.100",
        cobbler_system => "node1",
        path => "/var/lib/libvirt/images",
        system_name => "VM1"
    }
}

class task_ms1__koan_3a_3aconfig___56_4d2(){
    koan::config { "VM2":
        bridge => "br0",
        cobbler_server => "10.10.10.100",
        cobbler_system => "node2",
        path => "/var/lib/libvirt/images",
        system_name => "VM2"
    }
}


node "ms1" {

    class {'litp::ms_node':}


    class {'task_ms1__koan_3a_3aconfig___56_4d1':
    }


    class {'task_ms1__koan_3a_3aconfig___56_4d2':
    }


}