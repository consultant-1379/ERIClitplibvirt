# Defining the Libvirt install adaptor
define libvirt::install_adaptor (
            $version                # string
            ) {

  package { 'ERIClitpmnlibvirt_CXP9031529':
    ensure  => $version,
    install_options => "--disableplugin=post-transaction-actions",
  }

}
