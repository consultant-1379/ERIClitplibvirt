# Defining the Libvirt write file.
define libvirt::write_file (
            $content,                # string
            $target_path,            # string
            $file_name               # string
            ) {

  require libvirt

  # Write string to file.
  $target_file_path = "${target_path}/${file_name}"

  file { $target_file_path:
      ensure  => file,
      content => $content
    }
}
