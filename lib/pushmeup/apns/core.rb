require 'socket'
require 'openssl'
require 'json'

module APNS
  class Application

    #Accessors
    attr_accessor :host, :pem, :port, :pass, :app_id

    # Init method
    def initialize(host='gateway.sandbox.push.apple.com', pem=nil, port=2195, pass=nil)
      @host = host unless host == nil
      @pem = pem unless pem == nil
      @port = port unless port == nil
      @pass = pass unless pass == nil
      @retries = 3
    end

    # Send notification 
    def send_notification(device_token, message)
      n = APNS::Notification.new(device_token, message)
      self.send_notifications([n])
    end
    
    # Send notifications
    def send_notifications(notifications)
      self.with_connection do
        notifications.each do |n|
          @ssl.write(n.packaged_notification)
        end
      end
    end
    
    def feedback
      sock, ssl = self.feedback_connection

      apns_feedback = []

      while line = ssl.read(38)   # Read lines from the socket
        line.strip!
        f = line.unpack('N1n1H140')
        apns_feedback << { :timestamp => Time.at(f[0]), :token => f[2] }
      end

      ssl.close
      sock.close

      return apns_feedback
    end
    
    # Connection initialization and notifications sending
    def with_connection
      attempts = 1
      begin      
        open_socket_and_ssl_if_needed
        yield
      rescue StandardError, Errno::EPIPE
        close_socket_and_ssl
        return unless attempts < @retries
        attempts += 1
        retry
      end
    end

    # Open socket and ssl only if they are not already opened
    def open_socket_and_ssl_if_needed
      if @ssl.nil? || @sock.nil? || @ssl.closed? || @sock.closed?
        @sock, @ssl = self.open_connection
      end
    end

    # Close socked and ssl only if they are not nil
    def close_socket_and_ssl
      @ssl.close unless @ssl.nil?
      @sock.close unless @sock.nil?
    end

    protected

    def open_connection
      raise "The certificate data (pem) is missing" unless self.pem
      
      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(certificate_data)
      context.key  = OpenSSL::PKey::RSA.new(certificate_data, self.pass)

      sock         = TCPSocket.new(self.host, self.port)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
      ssl.connect

      return sock, ssl
    end
    
    def certificate_data
      @certificate ||= begin
        if File.file?(@pem)
          File.read(@pem)
        else
          @pem
        end
      end
    end
    
    def feedback_connection
      raise "The certificate data (pem) is missing" unless self.pem
      
      context      = OpenSSL::SSL::SSLContext.new
      context.cert = OpenSSL::X509::Certificate.new(certificate_data)
      context.key  = OpenSSL::PKey::RSA.new(certificate_data, self.pass)
      
      fhost = self.host.gsub('gateway','feedback')
      
      sock         = TCPSocket.new(fhost, 2196)
      ssl          = OpenSSL::SSL::SSLSocket.new(sock, context)
      ssl.connect

      return sock, ssl
    end
  end
end
