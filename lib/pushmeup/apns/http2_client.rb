# encoding: utf-8
require 'socket'
require 'openssl'
require 'json'
require 'net-http2'

require 'jwt'

module APNS

  class Http2Client

    attr_reader :host, :port, :key_id, :team_id

    def initialize(auth_key, key_id, team_id, mode = :development)
      check_openssl_version
      @mode = mode
      @host = production? ? 'api.push.apple.com' : 'api.development.push.apple.com'
      @auth_key = auth_key.is_a?(String) ? OpenSSL::PKey::EC.new(auth_key) : auth_key
      @key_id = key_id
      @team_id = team_id
      @client = NetHttp2::Client.new("https://#{@host}")
    end

    def production?
      @mode == :production
    end

    def send_notification(device_token, bundle_identifier, message)
      send_notifications([APNS::Notification.new(device_token, message)], bundle_identifier)
    end

    def send_notifications(notifications, bundle_identifier, close_connection = true)
      results = {}
      notifications.each do |notification|
        path = "/3/device/#{notification.device_token}"
        res = @client.call(:post, path, headers: headers(bundle_identifier), body: notification.to_json)
        results[notification.device_token] = res.body if !res.body.nil? && res.body.strip != ''
      end
      @client.close if close_connection
      results
    end

    def close
      @client.close
    end

    protected

    def headers(bundle_identifier)
      {
        'authorization' => "bearer #{jwt_token}",
        'content-type' => 'application/json',
        'apns-topic' => bundle_identifier,
      }
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
