require 'rex/proto/http'
require 'rex/socket/tcp'

class MetasploitModule < Msf::Auxiliary

 # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP Version Detection',
      'Description' => 'Display version information about each system.',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_wmap_options({
        'OrderID' => 2,
        'Require' => {},
      })

  end

def run_host(ip)
      socket = Socket.new(:INET, :STREAM)
      remote_host_address = Socket.check_host(datastore['RHOST'])
     

	begin
        socket.connect_nonblock(remote_host_address)
        report_service(:host => rhost, :port => rport, :sname => (ssl ? 'https' : 'http'), :info => fp)

	rescue Errno::EINPROGRESS

	ensure
		disconnect

    end

		_, sockets, _ = IO.select(nil, [socket], nil, TIMEOUT)
		if sockets

			puts "Port #{port} is open"

		else
	  
			puts "Port is closed"
		
		end
	end
end