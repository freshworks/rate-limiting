require "json"
require "rule"
require "ip_range"
require "rate_limit_html"
require 'timeout'

class RateLimiting

  SHARD = 1000
  RequestTimeoutRateLimit = 2
  IPRange = IpRange.new
  DDOS = 'ddos'.freeze
  HTTP_X_FW_RATELIMITING_MANAGED = 'HTTP_X_FW_RATELIMITING_MANAGED'.freeze
  TRUE_STRING = true.freeze

  def initialize(app, &block)
    @app = app
    @logger =  nil
    @rules = []
    @cache = {}
    block.call(self)
  end

  def call(env)
    request = Rack::Request.new(env)
    @logger = env['rack.logger']
    #  Rate limiting is done in HAProxy using sticky tables for IP, Domain
    #    and Path combinations, with hourly/minute level throttling
    #  Skip redundant processing with HTTP_X_FW_RATELIMITING_MANAGED header
    #  This header could be used for any external throttles
    respond(env, nil) if skip_on_header
    prefetch_cache_values(request)
    (limit_header = allowed?(request)) ? respond(env, limit_header) : rate_limit_exceeded(env['HTTP_ACCEPT'])
  end

  def prefetch_cache_values(request)
    @whitelisted = @blacklisted = @ddosed = nil
    return unless cache.respond_to?(:pipelined)

    begin
      res = cache.pipelined do
        cache.hexists(partioning_hash(request.ip), request.ip)
        cache.hexists(partioning_hash_blacklist(request.ip), request.ip)
        cache.get(DDOS)
      end
    rescue Exception => e
      NewRelic::Agent.notice_error(e)
      return
    end

    @whitelisted = res[0]
    @blacklisted = res[1]
    @ddosed = res[2].nil? ? false : res[2]
  end

  def respond(env, limit_header)
    status, header, response = @app.call(env)
    (limit_header.class == Hash) ? [status, header.merge(limit_header), response] : [status, header, response]
  end

  def rate_limit_exceeded(accept)
    case accept.to_s.gsub(/;.*/, "").split(',')[0]
    when "text/xml"         then message, type  = xml_error("403", "Rate Limit Exceeded"), "text/xml"
    when "application/json" then  message, type  = ["Rate Limit Exceeded"].to_json, "application/json"
    else
      message, type  = [RateLimitHtml::HTML], "text/html"
    end
    [403, {"Content-Type" => type}, message]
  end

  def define_rule(options)
    @rules << Rule.new(options)
  end

  def set_cache(cache)
    @cache = cache
  end

  def cache
    case @cache
      when Proc then @cache.call
      else @cache
    end
  end

  def cache_has?(key)
    case
    when cache.respond_to?(:get)
      cache.get(key) rescue false
    when cache.respond_to?(:has_key?)
      cache.has_key?(key)
    when cache.respond_to?(:exist?)
      cache.exist?(key)
    else false
    end
  end

  def cache_get(key)
    case
    when cache.respond_to?(:[])
      return cache[key]
    when cache.respond_to?(:get)
      return cache.get(key) || nil
    when cache.respond_to?(:fetch)
      return cache.fetch(key)
    end
  end

  def cache_set(key, value)
    case
    when cache.respond_to?(:[])
      begin
        cache[key] = value
      rescue TypeError => e
        cache[key] = value.to_s
      end
    when cache.respond_to?(:set)
      cache.set(key, value)
    when cache.respond_to?(:write)
      begin
        cache.write(key, value)
      rescue TypeError => e
        cache.write(key, value.to_s)
      end
    end
  end

  def cache_hexists(hash,field)
    case
    when cache.respond_to?(:hexists)
      return cache.hexists(hash, field)
    end
  end

  def cache_setex(key,expiry,value)
    case
    when cache.respond_to?(:setex)
      return cache.setex(key,expiry,value)
    end
  end

  def cache_rpush(key,value)
    case
    when cache.respond_to?(:rpush)
      cache.rpush(key,value)
    end
  end

  def whitelist?(key)
    return @whitelisted unless @whitelisted.nil?
    hash_key = partioning_hash(key)
    field = key
    cache_hexists(hash_key,field)
  end 

  def blacklist?(key)
    return @blacklisted unless @blacklisted.nil?
    hash_key = partioning_hash_blacklist(key)
    cache_hexists(hash_key,key)
  end

  def blacklisting_ip(request)
    return true if blacklist?(request.ip)
    if ddos
      return true if IPRange.check_presence_of_ip(request.ip)
    end
    return false
  end

  def partioning_hash(ip)
    "whitelist"+(ip.gsub(".","").to_i%1000).to_s
  end

  def partioning_hash_blacklist(ip)
    "blacklist"+(ip.gsub(".","").to_i%1000).to_s
  end

  def logger
    @logger || Rack::NullLogger.new(nil)
  end

  def allowed?(request)
    begin
      return true if whitelist?(request.ip)
      return false if blacklisting_ip(request)
      if rule = find_matching_rule(request)
        apply_rule(request, rule)
      else
        true
      end
    rescue Exception => e
      NewRelic::Agent.notice_error(e)
      true
    end
  end

  def ddos
    return @ddosed unless @ddosed.nil?
    cache_has?(DDOS)
  end

  def find_matching_rule(request)
    @rules.each do |rule|
      return rule if request.path =~ rule.match
    end
    nil
  end

  def apply_rule(request, rule)
    key = rule.get_key(request)
    if cache_has?(key) && (record = cache_get(key))    
      logger.debug "[#{self}] #{request.ip}:#{request.path}: Rate limiting entry: '#{key}' => #{record}"
      current_time = Time.now
      if (reset = Time.at(record.split(':')[1].to_i)) > current_time
        # rule hasn't been reset yet
        times = record.split(':')[0].to_i
        cache_setex(key, (reset.to_i - current_time.to_i ), "#{times + 1}:#{reset.to_i}")
        if (times) < rule.limit
          # within rate limit
          response = get_header(times + 1, reset, rule.limit)
        else
          logger.debug "[#{self}] #{request.ip}:#{request.path}: Rate limited; request rejected."
          return false
        end
      else
        response = get_header(1, rule.get_expiration, rule.limit)
        cache_setex(key, rule.get_expiration_sec, "1:#{rule.get_expiration.to_i}")
      end
    else
      response = get_header(1, rule.get_expiration, rule.limit)
      cache_setex(key, rule.get_expiration_sec, "1:#{rule.get_expiration.to_i}")
    end
    response
  end

  def get_header(times, reset, limit)
    {'x-RateLimit-Limit' => limit.to_s, 'x-RateLimit-Remaining' => (limit - times).to_s, 'x-RateLimit-Reset' => reset.strftime("%d%m%y%H%M%S") }
  end

  def xml_error(code, message)
    "<?xml version=\"1.0\"?>\n<error>\n  <code>#{code}</code>\n  <message>#{message}</message>\n</error>"
  end

  def skip_on_header(request)
    request.env[HTTP_X_FW_RATELIMITING_MANAGED] == TRUE_STRING
  end
end
