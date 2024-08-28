# Defining the Libvirt remove_adaptor file
define libvirt::remove_adaptor (
        ) {

  package { 'ERIClitpmnlibvirt_CXP9031529':
    ensure  => absent,
    install_options => "--disableplugin=post-transaction-actions",
  }

}   
