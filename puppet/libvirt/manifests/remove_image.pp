# Removes the image file when it is no longer needed
define libvirt::remove_image (
            $target_path,             # string
            $file_name                # string
        ) {
  $target_file_path = "${target_path}${file_name}"
  $target_md5_file_path = "${target_path}${file_name}.md5"
  $target_checksum_file_path = "${target_path}${file_name}_checksum.md5"

  file { [$target_file_path, $target_md5_file_path, $target_checksum_file_path]:
    ensure  => absent
  }
}
