metadata    :name        => "libvirt_mco_agent",
            :description => "API to access libvirt cli commands",
            :author      => "Ericsson AB",
            :license     => "Ericsson",
            :version     => "1.0",
            :url         => "http://ericsson.com",
            :timeout     => 1000

action "restart", :description => "restarts a vm service with specific commands" do
    display :always

    input  :service_name,
           :prompt      => "Service name",
           :description => "The name of the service to restart",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    input  :stop_command,
           :prompt      => "Stop Command",
           :description => "The stop command used for restarting the vm",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    input  :start_command,
           :prompt      => "Start Command",
           :description => "The start command used for restarting the vm",
           :type        => :string,
           :validation  => '',
           :optional    => true,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "The stdout from running the command",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end

action "node_image_cleanup", :description => "removes unused vm images from instance dir" do
    display :always

    input  :image_whitelist,
           :prompt      => "Image Whitelist",
           :description => "List of image files to keep",
           :type        => :string,
           :validation  => '',
           :optional    => false,
           :maxlength   => 0

    output :retcode,
           :description => "The exit code from running the command",
           :display_as => "Result code"

    output :out,
           :description => "List of files deleted",
           :display_as => "out"

    output :err,
           :description => "The stderr from running the command",
           :display_as => "err"

end
