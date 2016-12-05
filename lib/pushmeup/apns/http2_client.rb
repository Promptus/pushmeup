# encoding: utf-8
require 'socket'
require 'openssl'
require 'json'
require 'http/2'
require 'jwt'

module APNS

  class Http2Client

    attr_reader :host, :port, :key_id, :team_id

    def initialize(auth_key, key_id, team_id, mode = :development, port = 443)
      check_openssl_version
      @mode = mode
      @host = production? ? 'api.push.apple.com' : 'api.development.push.apple.com'
      @port = port
      @auth_key = auth_key.is_a?(String) ? OpenSSL::PKey::EC.new(auth_key) : auth_key
      @key_id = key_id
      @team_id = team_id
    end

    def production?
      @mode == :production
    end

    def send_notification(device_token, bundle_identifier, message)
      send_notifications([APNS::Notification.new(device_token, message)], bundle_identifier)
    end

    def send_notifications(notifications, bundle_identifier)
      @queue = notifications
      send_next_notification(bundle_identifier)
    end

    def send_next_notification(bundle_identifier)
      with_connection do
        if notification = @queue.pop
          stream = @conn.new_stream
          stream.on(:close) { send_next_notification(bundle_identifier) }
          json = notification.to_json
          headers = {
            ':scheme' => 'https',
            ':method' => 'POST',
            ':path' => "/3/device/#{notification.device_token}",
            'authorization' => "bearer #{jwt_token}",
            'content-type' => 'application/json',
            'apns-topic' => bundle_identifier,
            'content-length' => json.bytesize.to_s # should be less than or equal to 4096 bytes
          }
          stream.headers(headers, end_stream: false)
          stream.data(json)
          while !@ssl.closed? && !@ssl.eof?
            data = @ssl.read_nonblock(1024)
            begin
              @conn << data
            rescue => e
              close_socket_and_ssl
              raise
            end
          end
        else
          close_socket_and_ssl
        end
      end
    end

    def with_connection
      if @ssl.nil? || @ssl.closed?
        open_connection
      end
      yield
    end

    # Close socked and ssl only if they are not nil
    def close_socket_and_ssl
      @ssl.close unless @ssl.nil?
      @sock.close unless @sock.nil?
    end

    protected

    def open_connection
      raise "The server auth key (pem) is missing" unless @auth_key
      context = OpenSSL::SSL::SSLContext.new
      context.verify_mode = OpenSSL::SSL::VERIFY_NONE
      @sock = TCPSocket.new(@host, @port)
      @ssl = OpenSSL::SSL::SSLSocket.new(@sock, context)
      @ssl.sync_close = true
      @ssl.connect

      @conn = HTTP2::Client.new
      @conn.on(:frame) do |bytes|
        @ssl.print bytes
        @ssl.flush
      end
    end

    def jwt_token
      if @jwt_token.nil? || Time.now.to_i - @token_time.to_i > 2700 # 45 Minutes
        @token_time = Time.now
        header = { "kid": key_id }
        claims = { "iss": team_id, "iat": @token_time.to_i }
        @jwt_token = JWT.encode claims, @auth_key, 'ES256', header
      end
      @jwt_token
    end

    def check_openssl_version
      _, major, minor, bugfix = OpenSSL::OPENSSL_VERSION.match(/(\d+)\.(\d+)\.(\d+)/).to_a
      raise 'OpenSSL version 1.0.1 or later required' if major.to_i < 1
      raise 'OpenSSL version 1.0.1 or later required' if major.to_i == 1 && minor.to_i == 0 && bugfix.to_i < 1
    end

  end

end
