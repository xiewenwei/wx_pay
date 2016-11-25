require 'net/http'
require 'json'
require 'cgi'
require 'securerandom'

module WxPay
  module Service
    GATEWAY_URL = 'https://api.mch.weixin.qq.com'

    def self.generate_authorize_url(redirect_uri, state = nil)
      state ||= SecureRandom.hex 16
      "https://open.weixin.qq.com/connect/oauth2/authorize?appid=#{WxPay.appid}&redirect_uri=#{CGI::escape redirect_uri}&response_type=code&scope=snsapi_base&state=#{state}"
    end

    def self.authenticate(authorization_code, options = {})
      options = WxPay.extra_http_client_options.merge(options)
      url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=#{WxPay.appid}&secret=#{WxPay.appsecret}&code=#{authorization_code}&grant_type=authorization_code"

      # ::JSON.parse(RestClient::Request.execute(
      #   {
      #     method: :get,
      #     url: url
      #   }.merge(options)
      # ), quirks_mode: true)

      # TODO use options
      res = Net::HTTP.get(URI(url))
      if res.is_a?(Net::HTTPSuccess)
        ::JSON.parse(res.body)
      else
        raise "Caught error when call weixin."
      end
    end

    INVOKE_UNIFIEDORDER_REQUIRED_FIELDS = [:body, :out_trade_no, :total_fee, :spbill_create_ip, :notify_url, :trade_type]
    def self.invoke_unifiedorder(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        key: options.delete(:key) || WxPay.key,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      check_required_options(params, INVOKE_UNIFIEDORDER_REQUIRED_FIELDS)

      r = WxPay::Result.new(request_weixin("/pay/unifiedorder", params, options))

      yield r if block_given?

      r
    end

    INVOKE_CLOSEORDER_REQUIRED_FIELDS = [:out_trade_no]
    def self.invoke_closeorder(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        key: options.delete(:key) || WxPay.key,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      check_required_options(params, INVOKE_CLOSEORDER_REQUIRED_FIELDS)

      r = WxPay::Result.new(request_weixin("/pay/closeorder", params, options))

      yield r if block_given?

      r
    end

    GENERATE_APP_PAY_REQ_REQUIRED_FIELDS = [:prepayid, :noncestr]
    def self.generate_app_pay_req(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        partnerid: options.delete(:mch_id) || WxPay.mch_id,
        key: options.delete(:key) || WxPay.key,
        package: 'Sign=WXPay',
        timestamp: Time.now.to_i.to_s
      }.merge(params)

      check_required_options(params, GENERATE_APP_PAY_REQ_REQUIRED_FIELDS)

      params[:sign] = WxPay::Sign.generate(params)

      params
    end

    GENERATE_JS_PAY_REQ_REQUIRED_FIELDS = [:prepayid, :noncestr]
    def self.generate_js_pay_req(params, options = {})
      check_required_options(params, GENERATE_JS_PAY_REQ_REQUIRED_FIELDS)

      params = {
        appId: options.delete(:appid) || WxPay.appid,
        package: "prepay_id=#{params.delete(:prepayid)}",
        nonceStr: params.delete(:noncestr),
        timeStamp: Time.now.to_i.to_s,
        signType: 'MD5'
      }.merge(params)

      params[:paySign] = WxPay::Sign.generate(params)
      params
    end

    INVOKE_REFUND_REQUIRED_FIELDS = [:out_refund_no, :total_fee, :refund_fee, :op_user_id]
    def self.invoke_refund(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', ''),
      }.merge(params)

      params[:op_user_id] ||= params[:mch_id]

      check_required_options(params, INVOKE_REFUND_REQUIRED_FIELDS)

      options = {
        ssl_client_cert: options.delete(:apiclient_cert) || WxPay.apiclient_cert,
        ssl_client_key: options.delete(:apiclient_key) || WxPay.apiclient_key,
        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      }.merge(options)

      r = WxPay::Result.new(request_weixin("/secapi/pay/refund", params, options))

      yield r if block_given?

      r
    end

    REFUND_QUERY_REQUIRED_FIELDS = [:out_trade_no]
    def self.refund_query(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      check_required_options(params, ORDER_QUERY_REQUIRED_FIELDS)

      r = WxPay::Result.new(request_weixin("/pay/refundquery", params, options))

      yield r if block_given?

      r
    end

    INVOKE_TRANSFER_REQUIRED_FIELDS = [:partner_trade_no, :openid, :check_name, :amount, :desc, :spbill_create_ip]
    def self.invoke_transfer(params, options = {})
      params = {
        mch_appid: options.delete(:appid) || WxPay.appid,
        mchid: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      check_required_options(params, INVOKE_TRANSFER_REQUIRED_FIELDS)

      options = {
        ssl_client_cert: options.delete(:apiclient_cert) || WxPay.apiclient_cert,
        ssl_client_key: options.delete(:apiclient_key) || WxPay.apiclient_key,
        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      }.merge(options)

      r = WxPay::Result.new(request_weixin("/mmpaymkttransfers/promotion/transfers", params, options))

      yield r if block_given?

      r
    end

    INVOKE_REVERSE_REQUIRED_FIELDS = [:out_trade_no]
    def self.invoke_reverse(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      check_required_options(params, INVOKE_REVERSE_REQUIRED_FIELDS)

      options = {
        ssl_client_cert: options.delete(:apiclient_cert) || WxPay.apiclient_cert,
        ssl_client_key: options.delete(:apiclient_key) || WxPay.apiclient_key,
        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      }.merge(options)

      r = WxPay::Result.new(request_weixin("/secapi/pay/reverse", params, options))

      yield r if block_given?

      r
    end

    INVOKE_MICROPAY_REQUIRED_FIELDS = [:body, :out_trade_no, :total_fee, :spbill_create_ip, :auth_code]
    def self.invoke_micropay(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      check_required_options(params, INVOKE_MICROPAY_REQUIRED_FIELDS)

      options = {
        ssl_client_cert: options.delete(:apiclient_cert) || WxPay.apiclient_cert,
        ssl_client_key: options.delete(:apiclient_key) || WxPay.apiclient_key,
        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      }.merge(options)

      r = WxPay::Result.new(request_weixin("/pay/micropay", params, options))

      yield r if block_given?

      r
    end

    ORDER_QUERY_REQUIRED_FIELDS = [:out_trade_no]
    def self.order_query(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)


      r = WxPay::Result.new(request_weixin("/pay/orderquery", params, options))
      check_required_options(params, ORDER_QUERY_REQUIRED_FIELDS)

      yield r if block_given?

      r
    end

    DOWNLOAD_BILL_REQUIRED_FIELDS = [:bill_date, :bill_type]
    def self.download_bill(params, options = {})
      params = {
        appid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', ''),
      }.merge(params)

      check_required_options(params, DOWNLOAD_BILL_REQUIRED_FIELDS)

      r = request_weixin("/pay/downloadbill", params, options.dup.merge(not_to_hash: true))

      yield r if block_given?

      r
    end

    def self.sendgroupredpack(params, options={})
      params = {
        wxappid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      #check_required_options(params, INVOKE_MICROPAY_REQUIRED_FIELDS)

      options = {
        ssl_client_cert: options.delete(:apiclient_cert) || WxPay.apiclient_cert,
        ssl_client_key: options.delete(:apiclient_key) || WxPay.apiclient_key,
        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      }.merge(options)

      r = WxPay::Result.new(request_weixin("/mmpaymkttransfers/sendgroupredpack", params, options))

      yield r if block_given?

      r
    end

    def self.sendredpack(params, options={})
      params = {
        wxappid: options.delete(:appid) || WxPay.appid,
        mch_id: options.delete(:mch_id) || WxPay.mch_id,
        nonce_str: SecureRandom.uuid.tr('-', '')
      }.merge(params)

      #check_required_options(params, INVOKE_MICROPAY_REQUIRED_FIELDS)

      options = {
        ssl_client_cert: options.delete(:apiclient_cert) || WxPay.apiclient_cert,
        ssl_client_key: options.delete(:apiclient_key) || WxPay.apiclient_key,
        verify_ssl: OpenSSL::SSL::VERIFY_NONE
      }.merge(options)

      r = WxPay::Result.new(request_weixin("/mmpaymkttransfers/sendredpack", params, options))

      yield r if block_given?

      r
    end

    class << self
      private

      def check_required_options(options, names)
        return unless WxPay.debug_mode?
        names.each do |name|
          warn("WxPay Warn: missing required option: #{name}") unless options.has_key?(name)
        end
      end

      def make_payload(params)
        sign = WxPay::Sign.generate(params)
        params.delete(:key) if params[:key]
        "<xml>#{params.map { |k, v| "<#{k}>#{v}</#{k}>" }.join}<sign>#{sign}</sign></xml>"
      end

      def request_weixin(url, params, options = {})
        options = WxPay.extra_http_client_options.merge(options)

        # RestClient::Request.execute(
        #   {
        #     method: :post,
        #     url: url,
        #     payload: make_payload(params),
        #     headers: { content_type: 'application/xml' }
        #   }.merge(options)
        # )

        # TODO use options
        not_to_hash = opitons.delete(:not_to_hash)

        uri = URI("#{GATEWAY_URL}#{url}")
        req = Net::HTTP::Post.new(uri)
        req.body = make_payload(params)
        req.content_type = "application/xml"

        res = Net::HTTP.start(uri.hostname, uri.port) do |http|
          http.request(req)
        end

        if res.is_a?(Net::HTTPSuccess)
          if not_to_hash
            res.body
          else
            WxPay::Utils.xml_to_hash(res.body)
          end
        else
          raise "Caught error when call weixin."
        end
      end
    end
  end
end
