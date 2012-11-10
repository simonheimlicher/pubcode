#!/usr/bin/ruby

# == Synopsis 
#   This sets up the routing and DNS environment 
#   to enable productive work in companies with separate networks
#   for corporate services and Internet access.
#
# == CAVEAT
#    You absolutely NEED to edit this script before it will do
#    anything useful. In particular, you need to replace all IP
#    addresses with the ones matching your environment.
# 
# == Prerequisites
#    The machine has two network interfaces:
#    (i)  one is connected to the Corporate network, through which 
#         internal servers (with public or private IP) are accessed, 
#    (ii) the other is connected to the Other network, which allows 
#         accessing hosts in the local subnet (printers etc.) as well
#         as any host in the Internet at large.
#
#    These interfaces are recognized based on the IP of their default
#    gateway they have been assigned; see
#    CORPORATE_IP_PATTERN and OTHER_IP_PATTERN below, respectively.
#
#    To top things off, you can also enable VPN after the multihome
#    routing is set up. The script will look for a service that has
#    type :tunnel and then use AppleScript to enable that service,
#    which will connect the VPN if it indeed is a VPN service.
#
#    If your environment differs, things can and will go wrong, so
#   
#         USE THIS AT YOUR OWN RISK.
#   
#
# == Examples
#   Enable routing and DNS using detected network interfaces:
#
#     multihome_setup
#
#   Enable routing and DNS using detected network interfaces and then
#   also enable VPN over the network connected to the Internet:
#
#     multihome_setup --vpn
#
#   Restore default routing and DNS setup:
#     multihome_setup restore
#
# == Usage 
#   multihome_setup [setup | restore] [options]
#
#   For help, use: multihome_setup -h
#
# == Options
#   -h, --help          Displays help message
#   -v, --verbose       Verbose output
#   -t, --vpn           Enable VPN
#   -d, --debug         Debug output
#
# == Author
#   Simon Heimlicher
#
# == Copyright
#   Copyright (c) 2011-2012 Simon Heimlicher.

require 'optparse' 
require 'rdoc/usage'
require 'ostruct'
require 'date'
require 'open3'
require 'pp'

class MultiHome
  VERSION = '0.0.3'
  
  CORPORATE_ID = 'Corporate'
  # Subnetworks to route through corporate interface
  # Note that '255.255.255.255/16' is an invalid network address
  # that is used to keep you from running this script as is.
  CORPORATE_NET  = ['255.255.255.255/16', '1.1.0.0/16']
  # Regex to detect the interface that is connected to corporate network
  # The pattern is matched against the IP address of the DEFAULT ROUTE 
  # of the interface, not the IP address of the interface itself
  CORPORATE_IP_PATTERN = /10\.1[21]\.[0-9]+\.[0-9]+/

  OTHER_ID = 'Other'
  OTHER_NET = ['10.0.0.0/16']
  # Regex to detect the interface connected to other network
  # The pattern is matched against the IP address of the DEFAULT ROUTE 
  # of the interface, not the IP address of the interface itself
  OTHER_IP_PATTERN = /10\.0\.[0-9]+\.[0-9]+/

  # Regex to match any IP address
  REX_IP = /(?:\d{1,3}\.){3}\d{1,3}/
  # Path to resolver file for legacy applications
  RESOLV_CONF = '/etc/resolv.conf'
  
  # Path to BIND config file
  BIND_CONFIG_FILE = '/etc/named.conf'
  BIND_CONFIG_ORIG_FILE = '/etc/named.conf_shz_original'
  BIND_CONFIG_TMP_FILE = '/tmp/named.conf_shz_tmp'

  # Corporate nameservers
  BIND_CORPORATE_NS = '1.1.1.1; 1.1.1.2;'
  # Other nameservers (note: those are not necessarily identical 
  # to those that are used for Internet hosts)
  BIND_OTHER_NS = '10.0.0.250; 10.0.0.251;'
  
  # FIXME: Set to true when done adapting the parameters
  PARAMETERS_ADAPTED = false
  
#######################################################################
# NO NEED TO EDIT BELOW THIS LINE
#######################################################################
  
  # This should not be needed as we keep a backup copy of the original
  # /etc/named.conf around, but if that gets lost, we will restore 
  # the below configuration, which is the default on OS X Lion 10.7.2
  BIND_CONFIG_DARWIN = <<SHZ_EOF
//
// Include keys file
//
include "/etc/rndc.key";

// Declares control channels to be used by the rndc utility.
//
// It is recommended that 127.0.0.1 be the only address used.
// This also allows non-privileged users on the local host to manage
// your name server.

//
// Default controls
//
controls {
  inet 127.0.0.1 port 54 allow {any;}
  keys { "rndc-key"; };
};

options {
  directory "/var/named";
  /*
   * If there is a firewall between you and nameservers you want
   * to talk to, you might need to uncomment the query-source
   * directive below.  Previous versions of BIND always asked
   * questions using port 53, but BIND 8.1 uses an unprivileged
   * port by default.
   */
  // query-source address * port 53;
};
// 
// a caching only nameserver config
// 
zone "." IN {
  type hint;
  file "named.ca";
};

zone "localhost" IN {
  type master;
  file "localhost.zone";
  allow-update { none; };
};

zone "0.0.127.in-addr.arpa" IN {
  type master;
  file "named.local";
  allow-update { none; };
};

logging {
        category default {
                _default_log;
        };

        channel _default_log  {
                file "/Library/Logs/named.log";
                severity info;
                print-time yes;
        };
};
SHZ_EOF

  attr_reader :options

  def initialize(arguments, stdin)

    @arguments = arguments
    @stdin = stdin
		@is_root = ( Integer(`/usr/bin/id -u`) == 0 )
    
    # Set defaults
    @options = {
      :verbose => (ENV['VERBOSE'] or false),
      :debug => (ENV['DEBUG'] or false),
      :wait => ( (ENV['WAIT'] and ENV['WAIT'] !~ /0|false|no/) or 30),
      :restore => ( (ENV['RESTORE'] and ENV['RESTORE'] !~ /0|false|no/ ) or false),
      :vpn => ( (ENV['VPN'] and ENV['VPN'] =~ /1|true|yes/ ) or false),
    }
    @device = {
      'en0'   => { :type => :device },  # en0:   Network interface
      'en1'   => { :type => :device },  # en1:   Network interface
      'en2'   => { :type => :device },  # en2:   Network interface
      'en3'   => { :type => :device },  # en3:   Network interface
      'en4'   => { :type => :device },  # en4:   Network interface
      'en5'   => { :type => :device },  # en5:   Network interface
      'utun0' => { :type => :tunnel },  # utun0: VPN tunnel
      'utun1' => { :type => :tunnel },  # utun1: VPN tunnel
      'utun2' => { :type => :tunnel },  # utun2: VPN tunnel
      'utun3' => { :type => :tunnel },  # utun3: VPN tunnel
    }
    
    @dns = {
      # Default nameservers to use for Internet access;
      # may be identical or different from what you get via DHCP.
      :default => ['1.2.3.4', '1.2.3.5']
    }
    
    # Mapping from interface ('en0' or 'en1') to network :corporate or :other
    @network_map = {
      :corporate    => {:id => CORPORATE_ID,  :pattern => CORPORATE_IP_PATTERN},
      :other        => {:id => OTHER_ID, :pattern => OTHER_IP_PATTERN},
    }
    @service     = {}

  end

  # Parse options, check arguments, then process the command
  def run
        
    # Define options
    opts = OptionParser.new
    opts.banner = "Usage: #{File.basename($0)} [options] {setup|restore}"
    opts.on('-h', '--help') do
      @options[:usage] = true
    end
    opts.on( '-v', '--verbose', 'Print progress to STDERR' ) do
      @options[:verbose] = true
    end
    opts.on( '-d', '--debug', 'Print debug output to STDERR' ) do
      @options[:verbose] = true
      @options[:debug] = true
    end
    opts.on( '-w', '--wait', 
      'Wait [30] seconds for network interfaces' ) do |a|
      @options[:wait] = a
    end
    opts.on( '--corporate INTERFACE', 
      'Select INTERFACE for corporate network' ) do |a|
      @network_map[:corporate][:pattern] = /#{a}/
    end
    opts.on( '--other INTERFACE', 
      'Select INTERFACE for other network' ) do |a|
      @network_map[:other][:pattern] = /#{a}/
    end
    opts.on( '--vpn', 'Enable VPN' ) do |a|
      @options[:vpn] = a
    end
    if CORPORATE_NET.include?('255.255.255.255/16') ||
      ! PARAMETERS_ADAPTED
      RDoc::usage_no_exit()
      puts opts
      puts "\n###\n### YOU NEED TO READ, UNDERSTAND,\n"\
      "### AND FINALLY EDIT THIS SCRIPT\n"\
      "### BEFORE YOU CAN USE IT\n###\n\n"
      return false
    end
    begin
      opts.parse!(@arguments)
    rescue OptionParser::InvalidOption => e
      RDoc::usage_no_exit()
      puts e
      puts opts
      return false
    end
    if @options[:usage]
      RDoc::usage_no_exit()
      puts opts
      return false
    end
    if parsed_arguments? 
      process_command
    else
      puts "#{File.basename(__FILE__)} version #{VERSION}"
      RDoc::usage_no_exit()
      puts opts
      exit 1
    end
      
  end
  
  protected
  	def leave(str='Fatal Error',errno=1)
			warn str
			exit errno
		end

    # True if required arguments were provided
    def parsed_arguments?
      return true if @arguments.empty?
      case @arguments.length
      when 1
        case @arguments[0]
        when 'setup'
          @options[:restore] = false
        when 'restore'
          @options[:restore] = true
        else
          return false
        end
      else
        return false
      end
      return true
    end
    
    def vrb(s)
      puts s if (@options[:verbose] or @options[:debug])
      return true
    end
    def dbg(s)
      puts s if @options[:debug]
      return true
    end

    def runcmd(cmd, opts = {})
      cmd = '/usr/bin/sudo '+cmd unless (@is_root or not opts[:privileged])
			cmd = "PATH='/usr/bin:/bin:/usr/sbin:/sbin' "+cmd
      if @options[:verbose]
        opts_str = ''
        unless opts.empty?
          opts_str = '['
          opts.each { |k, v| opts_str += " #{k}=#{v}" }
          opts_str += ' ]'
        end
        dbg "runcmd[is_root=#{@is_root}] #{opts_str}\n  #{cmd}"
      end
      so = se = nil
      Open3.popen3(cmd) do |stdin, stdout, stderr|
        so = so.chomp! unless (so = stdout.read) == nil
        se = se.chomp! unless (se = stderr.read) == nil
        unless (opts.has_key? :silent and opts[:silent])
          if  @options[:verbose]
             puts so.gsub(/^/, '1> ') if so
             puts se.gsub(/^/, '2> ') if se
          else
             warn se.gsub(/^/, '2> ') if se
          end
        end
      end
      if ($?.success? or (opts.has_key? :ignore and opts[:ignore]) )
        return so
      end
      warn("\n###\n###Running command\n"+
      "\n###    #{cmd}\n###\n###\nfailed\n\n")
      leave("Fatal error running command \"#{cmd}\"")
    end
    
    def process_command()

      if @options[:verbose] then 
        verbose = true
        puts "* * * Verbose reporting enabled"
      end
      if @options[:vpn] then 
        puts "* * * VPN will be enabled"
      end


      def setup_multihome()
        vrb "\nBeginning to set up multihome routing\n"
        timeout = Time.now + @options[:wait].to_i
        missing = []
        while Time.now.to_i < timeout.to_i do
          if _discover_services()
            _map_interfaces()
            missing = []
            @network_map.each do |netid, net|
              if (net[:device] and @service[net[:device]][:router])
                vrb "Network #{net[:id]} connected via device #{net[:device]}"
              else
                missing << netid
              end
            end
            if missing.empty?
              vrb "\nPrepare multihome routing..."
              if @options[:vpn] and not _connect_vpn()
								vrb "\nFailed to connect to VPN\n"
								return false
							end
              if not _route_config()
								vrb "\nFailed to set up routing\n"
								return false
							end
              if not _bind_config()
								vrb "\nFailed to set up DNS server\n"
                return false
							end

              vrb "\nSet up multihome routing\n"
              return true
            else
              missing.each { |m| 
                vrb "Waiting #{(timeout-Time.now).round} seconds "+
                "for connection to #{@network_map[m][:id]} network." 
              }
              vrb""
            end
          else
            vrb "Waiting #{(timeout-Time.now).round} seconds "+
            "for default route to become available"
          end
          sleep 1
        end

        warn "Fatal error: lacking network connectivity: "
        missing.each do |m|
          warn "  Not connected to #{@network_map[m][:id]} network." 
        end
        return false
      end

      def restore_default()
        vrb "\nBeginning to restore default setup\n"        
        _discover_services()
        _disconnect_vpn()
        _route_config_restore()
        _bind_config_restore()
        vrb "\nRestored default setup\n"
      end
      
      # If option 'restore' is not given, try to set up multihome;
      # if that fails, restore default configuration
			restore = @options[:restore]
      unless restore
        vrb "Setup multi-home routing..."
        unless setup_multihome()
					restore = true
        	warn "\33[2J\n\n################### Failed to set up multi-home routing #####################\n\33[2J\n"
        	warn "Restoring default setup"
				end
      end
      restore_default() if restore
    end
    
    def _dump_routes_v4()
      if @options[:verbose]
        rex_device = Regexp.new('^(?:'+@device.keys.join('|')+')$')
        runcmd("/usr/sbin/netstat -rn -f inet", {:silent=>true}).each do |l|
          ls = l.split(/\s+/)
          if (ls [2] and ls[2].match(/^[^I]+$/)) and
            (ls [5] and ls[5].match(rex_device))
            vrb l
          end
        end
      end
    end

    def _service_name(dev)
      s = runcmd("/usr/sbin/networksetup -listnetworkserviceorder", 
      {:silent => true})
      r = %r{\([0-9]+\)\s*([^)\n]+)\n\([^\n]*Device: #{dev}}m
      s.match(r)[1]
    end
    def _service_router(srv)
      s = runcmd("/usr/sbin/networksetup -getinfo '#{srv}'", 
      {:silent => true})
      r = %r{Router:\s*(.+)}
      begin
        s.match(r)[1]
      rescue NoMethodError
        return nil
      end
    end

    def _service(dev)
      dbg "Determine service using device #{dev}"
      srv = {:device => dev}
      srv[:service_name] = _service_name(dev)
      dbg "  service name: #{srv[:service_name]}"
      vrb "Determine router of service #{srv[:service_name]}"
      dbg[:router] = _service_router(srv[:service_name])
      dbg "  router: #{srv[:router]}"
      return srv
    end

    def _route(r)
      if @options[:verbose]
        runcmd("/sbin/route -n #{r}", {:privileged => true})
      else
        runcmd("/sbin/route -n #{r}", {:privileged => true, :silent => true})
      end
    end
    def _route_delete(r)
      dbg "Wait for route #{r} to go down..." 
      i = 0
      while (i+=1) < 10 and ! _route("delete #{r}")
        dbg "#{i}.. "
        sleep 0.2
      end
    end
    def _route_add(n, dev)
      r = @service[dev][:router]
      dbg "Wait for route to #{n} via #{r} to come up..." 
      i = 0
      while (i+=1) < 10 and ! _route("add #{n} #{r}")
        dbg "#{i}.. "
        sleep 0.2
      end
    end
    def _route_config()
      dbg "\n################################################################################"
      dbg "###                                 Before                                   ###\n"
      _dump_routes_v4()
      dbg "################################################################################\n"
      
      CORPORATE_NET.each do |n|
        dbg "\n* * * Add route for corporate network \"#{n}\""
        _route_delete("-net #{n}")
        _route_add("-net #{n}", @network_map[:corporate][:device])
      end
      dbg "\n################################################################################"
      dbg "###                                 After                                    ###\n"
      _dump_routes_v4()
      dbg "################################################################################\n"
    end      
    def _route_config_restore()
      dbg "\n################################################################################"
      dbg "###                                 Before                                   ###\n"
      _dump_routes_v4()
      dbg "################################################################################\n"

      CORPORATE_NET.each do |n|
        dbg "\n* * * Remove route to network \"#{n}\""
        _route_delete("-net #{n}")
      end

      sleep 0.5

      # First delete default route
      _route_delete("-net default")
      # Then add the default route to lowest order device having router
      dbg "Determine primary active network service"
      pri = nil
      @service.each do |dev, srv|
        if srv[:router] and srv[:router].match(REX_IP)
          next if pri and pri[:order] < srv[:order]
          pri = srv
        end
      end
      if pri
        dbg "  Primary device: #{pri[:device]} order: #{pri[:order]} router: #{pri[:router]}"
        _route_add("-net default", pri[:device])
      else
        warn "Failed to determine primary network service"
      end
      dbg "\n################################################################################"
      dbg "###                                 After                                    ###\n"
      _dump_routes_v4()
      dbg "################################################################################\n"
    end

    def _bind_config()
      return false unless _get_default_service()
      if ! FileTest.exists? '/etc/rndc.conf'
        runcmd("/bin/sh -c '/usr/sbin/rndc-confgen -b 256 > /etc/rndc.conf'", {:privileged => true})
      end
      if ! FileTest.exists? '/etc/rndc.key'
        runcmd("/bin/sh -c '/usr/bin/head -n5 /etc/rndc.conf | tail -n4 > /etc/rndc.key'", {:privileged => true})
      end
      if not runcmd("/bin/launchctl list org.isc.named", {:privileged => true, :silent => true})
        runcmd("/bin/launchctl load -F /System/Library/LaunchDaemons/org.isc.named.plist", {:privileged => true})
      end
      
      # Detect current nameserver
      # First remove any custom nameserver and restore the one 
      # obtained from VPN negotiation or DHCP in /etc/resolv.conf
			_reset_nameserver()
			ns_list = _get_nameserver()
      if ns_list.empty?
        bind_default_ns = @dns[:default].join('; ')+';'
      else
        bind_default_ns = ns_list.join('; ')+';'
      end
      
      vrb "BIND nameservers: #{bind_default_ns}"
      

      bind_config_multihome = <<SHZ_EOF
//
// Include keys file
//
include "/etc/rndc.key";

// Declares control channels to be used by the rndc utility.
//
// It is recommended that 127.0.0.1 be the only address used.
// This also allows non-privileged users on the local host to manage
// your name server.

//
// Allow control from localhost only
//
// MULTIHOME_BEGIN
controls {
    inet 127.0.0.1 port 953
        allow { 127.0.0.1; } keys { "rndc-key"; };
};
// MULTIHOME_END

options {
  directory "/var/named";
  /*
   * If there is a firewall between you and nameservers you want
   * to talk to, you might need to uncomment the query-source
   * directive below.  Previous versions of BIND always asked
   * questions using port 53, but BIND 8.1 uses an unprivileged
   * port by default.
   */
  // query-source address * port 53;
    // MULTIHOME_BEGIN
    // Listen to the loopback device only
    listen-on { 127.0.0.1; };
    listen-on-v6 { ::1; };

    // Forward all DNS queries to the default nameserver
    forwarders { #{bind_default_ns} };
    forward only;

    // Disable non-relevant operations
    allow-transfer { none; };
    allow-update-forwarding { none; };
    allow-notify { none; };
    // MULTIHOME_END
};

// MULTIHOME_BEGIN
// Zone for Corporate network
zone "example.com" in {
    type forward;
    forwarders { #{BIND_CORPORATE_NS} };
};
zone "example.org" in {
    type forward;
    forwarders { #{BIND_CORPORATE_NS} };
};
// Zone for Other network
zone "example.net" in {
    type forward;
    forwarders { #{BIND_OTHER_NS} };
};
// MULTIHOME_END
// 
// a caching only nameserver config
// 
zone "." IN {
  type hint;
  file "named.ca";
};

zone "localhost" IN {
  type master;
  file "localhost.zone";
  allow-update { none; };
};

zone "0.0.127.in-addr.arpa" IN {
  type master;
  file "named.local";
  allow-update { none; };
};

logging {
        category default {
                _default_log;
        };

        channel _default_log  {
                file "/Library/Logs/named.log";
                severity info;
                print-time yes;
        };
};
SHZ_EOF

      vrb "Replace DNS server configuration \"#{BIND_CONFIG_FILE}\""
      File.open("#{BIND_CONFIG_TMP_FILE}", 'w') {|f| f.write(bind_config_multihome) }
      dbg "Stopping DNS server"
      runcmd("/bin/launchctl stop org.isc.named", {:privileged => true})
      if ! FileTest.exists? BIND_CONFIG_ORIG_FILE
        runcmd("/bin/mv '#{BIND_CONFIG_FILE}' '#{BIND_CONFIG_ORIG_FILE}'", {:privileged => true})
      end
      runcmd("/bin/sh -c \"/bin/cat '#{BIND_CONFIG_TMP_FILE}' > '#{BIND_CONFIG_FILE}' \
          && rm '#{BIND_CONFIG_TMP_FILE}'\"", {:privileged => true})
      dbg "Start DNS server again"
      runcmd("/bin/launchctl start org.isc.named", {:privileged => true})

      # Set custom DNS servers to localhost
      dbg "Set DNS server of all interfaces to localhost [127.0.0.1]"
      _set_nameserver('127.0.0.1')
      # Flush DNS cache
      runcmd('/usr/bin/dscacheutil -flushcache', {:privileged => true})
      return true
    end

    def _bind_config_restore()
      vrb "Restoring DNS server config \"#{BIND_CONFIG_FILE}\""
      # Remove custom DNS servers by setting value to 'empty'
      dbg "Disable local DNS server on all interfaces"
      _reset_nameserver()
      if runcmd("/bin/launchctl list org.isc.named", {:privileged => true, :silent => true})
        dbg "Stopping DNS server"
        runcmd("/bin/launchctl unload /System/Library/LaunchDaemons/org.isc.named.plist", {:privileged => true})
      end
      if system("egrep -q MULTIHOME_BEGIN #{BIND_CONFIG_FILE}")
        if FileTest.exists? BIND_CONFIG_ORIG_FILE
          dbg "Restore saved DNS server config from \"#{BIND_CONFIG_ORIG_FILE}\""
          runcmd("/bin/mv '#{BIND_CONFIG_ORIG_FILE}' '#{BIND_CONFIG_FILE}'", {:privileged => true})
        else
          dbg "Error: saved DNS server config not found at \"#{BIND_CONFIG_ORIG_FILE}\""
          dbg "Restore default DNS server config"
          File.open("#{BIND_CONFIG_TMP_FILE}", 'w') {|f| f.write(BIND_CONFIG_DARWIN) }
          runcmd("/bin/sh -c \"/bin/cat '#{BIND_CONFIG_TMP_FILE}' > '#{BIND_CONFIG_FILE}' \
              && /bin/rm '#{BIND_CONFIG_TMP_FILE}'\"", {:privileged => true})
        end
      end
      # Flush DNS cache
      runcmd('/usr/bin/dscacheutil -flushcache', {:privileged => true})
    end

    def _get_default_service() 
      # Get default service from routing table
      tmp = runcmd("/sbin/route -n get default").match(/\s+interface: (.+)/)
      dev = tmp[1]
      srv = @service[dev]
    end
    def _get_nameserver()
      ns_list = []
      File.open("#{RESOLV_CONF}", 'r') do |file|
        ns_rex = /^[ \t]*nameserver[ \t]+(?=([^# \t\n]+)+)/
        file.grep(ns_rex) do |line|
          ns = line.scan(ns_rex)
          ns_list.push(ns) unless (line.match(/(?:127\.0\.0\.1|localhost)/) or ns_list.include?(ns) )
        end
      end
      return ns_list
    end
    def _set_nameserver(ns_list)
      srv = _get_default_service()
      runcmd("/usr/sbin/networksetup -setdnsservers '#{srv[:service_name]}' #{ns_list}", {:privileged => true})
      vrb "Set DNS server of network service \"#{srv[:service_name]}\": \n"+
      runcmd("/usr/sbin/networksetup -getdnsservers '#{srv[:service_name]}'", {:privileged => true, :silent => true})
    end
    def _reset_nameserver(srv=nil)
      srv_list = []
      if srv then 
        srv_list = [srv]
      else
        srv_list = @service.reject { |k,v| ! v[:type] == :interface  and ! v[:type] == :tunnel }.values
      end
      srv_list.each do |s|
        runcmd("/usr/sbin/networksetup -setdnsservers '#{s[:service_name]}' 'empty'", {:privileged => true})
        vrb "Reset DNS server of network service \"#{s[:service_name]}\": \n"
      end
    end
    def _service_connected(srv)
      s = runcmd("/usr/bin/osascript -e \"tell application \\\"System Events\\\" to get connected of configuration of service \\\"#{srv[:service_name]}\\\" of current location of network preferences\"", {:silent => true})
      if s == 'true'
        return true
      else
        return false
      end
    end
    def _connect_vpn()
      # Enable VPN
      @service.each do |v,srv|
        if srv[:type] == :tunnel
          # Assume this is the VPN service
          vrb "\nConnecting to VPN service \"#{srv[:service_name]}\""
          # First kill racoon
          runcmd('/usr/bin/killall racoon', {:silent => true, :ignore => true, :privileged => true})
          _reset_nameserver(srv)
          runcmd("/usr/bin/osascript -e \"tell application \\\"System Events\\\" to connect service \\\"#{srv[:service_name]}\\\" of current location of network preferences\"", {:silent => true})
          # Wait for VPN connection to become operational
          attempt = 150
          while not _service_connected(srv) and attempt > 0
            attempt -= 1
            sleep 0.2
          end
          return _service_connected(srv)
        end
				vrb "\nFailed to find VPN service in network configuration\n"
        return false
      end
    end
    def _disconnect_vpn()
      @service.each do |v,srv|
        if srv[:type] == :tunnel 
          dbg "Check if VPN service \"#{srv[:service_name]}\" is disconnected"
          if _service_connected(srv)
            # Assume this is the VPN service
            vrb "\nDisconnecting from VPN service \"#{srv[:service_name]}\""
            _reset_nameserver(srv)
            runcmd("/usr/bin/osascript -e \"tell application \\\"System Events\\\" to disconnect service \\\"#{srv[:service_name]}\\\" of current location of network preferences\"", {:silent => true})
            # Wait for VPN connection to go down
            attempt = 100
            while _service_connected(srv) and attempt > 0
              attempt -= 1
              sleep 0.2
            end
            if runcmd("/sbin/ifconfig #{srv[:device]}", {:silent => true})
              # Otherwise just kill racoon
              runcmd('/usr/bin/killall racoon', {:privileged => true, :silent => true, :ignore => true})
            end
          end
        end
      end
    end

    def _discover_services()
      # Check if there is a default route
      runcmd('/sbin/route -n get default', {:silent => true}) or return false
      vrb "Discover services"
      s = runcmd("/usr/sbin/networksetup -listnetworkserviceorder", {:silent => true})
      ord = name = dev = nil
      so = {}
      s.each_line do |l|
        if tmp = l.match(/^\(([0-9]+)\) (.+)$/)
          ord = tmp[1]; name = tmp[2]
          dbg "#{tmp[2]}"
        elsif ord and name
          if (tmp = l.match(/^\(.*Device:\s+([^)]+)\)/))
            dev = tmp[1]
            if @device.include? dev
              dbg "Determine router of service #{name}"
              router = _service_router(name)
              @service[dev] = {}
              @service[dev][:type] = :interface
              @service[dev][:service_name] = name
              @service[dev][:device] = dev
              @service[dev][:order] = ord
              @service[dev][:router] = router
              vrb "  Service: \"#{name}\" order: #{ord} "+
              "device: #{dev} router: #{router}"
            else
              dbg "  Ignore service: \"#{name}\" order: #{ord} "+
              "device: #{dev} router: #{router}"
            end
          else
            @device.each do |dev,v|
              if v[:type] == :tunnel
                router = nil
                if runcmd("/sbin/ifconfig #{dev}", {:silent=>true})
                  rex_tunnel = Regexp.new("[\s\S]*(#{REX_IP}) --> (#{REX_IP})", "m")
                  s = runcmd("/sbin/ifconfig #{dev}")
                  if (s and m = s.match(rex_tunnel))
                    dbg "  Since this is a tunnel service, router of service #{name} is the device itself: #{dev}"
                    router = dev
                  end
                end
                @service[dev] = {}
                @service[dev][:type] = :tunnel
                @service[dev][:service_name] = name
                @service[dev][:device] = dev
                @service[dev][:order] = ord
                @service[dev][:router] = router
                vrb "  Service: \"#{name}\" order: #{ord} "+
                "device: #{dev} router: #{router}"
              else
                dbg "  Ignore tunnel service: \"#{name}\" order: #{ord} "
              end
          end
        end
        ord = name = dev = nil
      end
      
      end
    end

    def _map_interfaces()
      vrb "Map interfaces to networks:"
      pp @network_map
      @network_map.each do |netid, net|
        @network_map[netid][:device] = nil
        dbg "  Look for network #{net[:id]} with default route matching #{net[:pattern]}"
        @service.each do |srvid, srv|
          if (srv.has_key? :device and (dev = srv[:device]) and
            srv.has_key? :router and (router = srv[:router]) )
            if router.match(net[:pattern] )
              dbg "    Matches service #{srv[:service_name]} [#{dev}] via #{router}"
              if @network_map[netid][:device] and
                @service[@network_map[netid][:device]][:order] < srv[:order]
                dbg "    Keep #{@service[@network_map[netid][:device]][:service_name]}"+
                " [#{@network_map[netid][:device]}]"
              else
                @network_map[netid][:device] = srv[:device]
                dbg "    Use #{@service[dev][:service_name]} [#{dev}]"
              end
            end
          end
        end
        unless @network_map[netid][:device]
          vrb "  Failed to detect interface to #{net[:id]} network"
      end
    end
  end

end

# Create and run the application
app = MultiHome.new(ARGV, STDIN)
app.run