module MCollective
  module Agent
    class Libvirt_mco_agent < RPC::Agent
      action "restart" do
        libdir = Config.instance.libdir
        for path in libdir
          script_path = path + "/mcollective/agent/libvirt_mco_agent.py"
          if File.exist?(script_path)
            break
          end
        end
        implemented_by script_path
      end
      action "node_image_cleanup" do
        libdir = Config.instance.libdir
        for path in libdir
          script_path = path + "/mcollective/agent/libvirt_mco_agent.py"
          if File.exist?(script_path)
            break
          end
        end
        implemented_by script_path
      end
    end
  end
end
