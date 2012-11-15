module EM::FTPD
  module Encryption

    def initialize(*args)
      super
      @command_channel_secure = false
      @client_wants_secure_data_channel = false
      @config ||= Configurator.new
    end

    def ssl_config
      {
          :private_key_file => @config.private_key_file,
          :cert_chain_file  => @config.cert_chain_file
      }
    end

    def ssl_config_for_data_channel
      ssl_config if client_wants_secure_data_channel?
    end

    def valid_ssl_config?
      EM.ssl? &&
          @config.private_key_file && File.readable?(@config.private_key_file) &&
          @config.cert_chain_file && File.readable?(@config.cert_chain_file)
    end

    def enforce_secure_command_channel?
      @config.enforce_tls
    end

    def command_channel_secure?
      @command_channel_secure
    end

    def ssl_handshake_completed
      @command_channel_secure = true
      super
    end

    def cmd_auth(param)
      send_param_required and return if param.nil?
      if param.upcase.eql?("TLS")
        send_response "234 AUTH command OK. Initializing SSL connection"
        start_tls(ssl_config)
      else
        send_response "504 Command not implemented for that parameter"
      end
    end

    def cmd_pbsz(param)
      send_param_required and return if param.nil?
      send_response("503 PBSZ needs AUTH TLS first") and return unless command_channel_secure?
      if param.upcase.eql?("0")
        @pbsz = param
        send_response "200 Command okay"
      else
        send_response "501 Syntax error in parameters or arguments"
      end
    end

    def cmd_prot(param)
      send_param_required and return if param.nil?
      send_response("503 Bad sequence of commands.") and return if @pbsz == nil
      if param.upcase.eql?("P")
        @client_wants_secure_data_channel = param.upcase == "P"
        send_response "200 Command okay"
      elsif %w{C S E}.include? param.upcase
        send_response "536 Security mechanism does not support"
      else
        send_response "504 Command not implemented for that parameter"
      end
    end

    def enforce_secure_data_channel?
      @config.enforce_data_tls
    end

    def client_wants_secure_data_channel?
      @client_wants_secure_data_channel
    end

    def reject_insecure_data_channel?
      enforce_secure_data_channel? && !client_wants_secure_data_channel?
    end

    def cmd_user(param)
      if enforce_secure_command_channel? && !command_channel_secure?
        send_response("521 This server enforces the use of AUTH TLS before log in")
      else
        super
      end
    end

    def cmd_stor(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_retr(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_nlst(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_list(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_stou(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end
    def cmd_appe(param); send_secure_data_channel_needed and return if reject_insecure_data_channel?; super; end

    def cmd_port(param); send_passive_ftp_needed and return if client_wants_secure_data_channel?; super; end
    def cmd_eprt(param); send_passive_ftp_needed and return if client_wants_secure_data_channel?; super; end


    def send_secure_data_channel_needed
      send_response("521 data connection cannot be opened with this PROT setting")
    end

    def send_passive_ftp_needed
      send_response("521 you have to use passive ftp with AUTH TLS for now")
    end

  end
end