require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP server scanner and what ports are open',
      'Description' => 'scans for information about the system.',
      'Author'      => 'thomas',
      'License'     => MSF_LICENSE
    )

    register_wmap_options({                                                                                                                                                                                                                   
      })                                                                                                                                                                                                                                   
  end   

	def run_host(host)
		begin
		connect #This means that it has connected to the server!
			respo = send_request_cgi!({'uri' => '/', 'method' => 'HEAD' })
			info = http_fingerprint(:responce => respo)
			time = Time.now
			report_loot(:host => rhost, :port => rport, :info => info)
			print_line("was there a SSL #{ssl} The host of the server is #{host} the ports that are open are shown as #{rport} and info about the server is #{info} and the time and date used #{time}") if info			
			rescue ::Timeout
		ensure
		disconnect
		end
	end
end
