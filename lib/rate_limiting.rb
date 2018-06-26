require "json"
require "rule"
require "ip_range"
require "rate_limit_html"
require 'timeout'

class RateLimiting

  SHARD = 1000
  RequestTimeoutRateLimit = 2
  IPRange = IpRange.new
  DDOS = "ddos"
  def initialize(app, &block)
    @app = app
    @logger =  nil
    @rules = []
    @cache = {}
    block.call(self)
  end

  def call(env)
    request = Rack::Request.new(env)
    (limit_header = allowed?(request)) ? respond(env, limit_header) : blocked_response(env['HTTP_ACCEPT'], env['CONTENT_TYPE'])
  end

  def respond(env, limit_header)
    status, header, response = @app.call(env)
    (limit_header.class == Hash) ? [status, header.merge(limit_header), response] : [status, header, response]
  end

  def blocked_response(accept, content_type)
    if (accept.to_s.gsub(/;.*/, "").split(',')[0] == "application/json") || (content_type == "application/json")
      message, type  = [{ message: @text_message || "Reached the limit of requests. Your access is temporarily restricted." }.to_json], "application/json"
    else
      message, type  = [@html_message || RateLimitHtml::HTML], "text/html"
    end
    [@status_code || 403, {"Content-Type" => type}, message]
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
    when cache.respond_to?(:has_key?)
      cache.has_key?(key)
    when cache.respond_to?(:get)
      cache.get(key) rescue false
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
    hash_key = partioning_hash(key)
    field = key
    cache_hexists(hash_key,field)
  end 

  def blacklist?(key)
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

  def set_logger(logger)
    @logger = logger
  end

  def logger
    @logger || Rack::NullLogger.new(nil)
  end

  def allowed?(request)
    begin
      @status_code = nil
      @text_message = nil
      @html_message = nil

      return true if whitelist?(request.ip)
      return false if blacklisting_ip(request)
      if rule = find_matching_rule(request)
        is_allowed = apply_rule(request, rule)
        @status_code = rule.get_status_code
        return is_allowed
      else
        true
      end
    rescue Exception => e
      NewRelic::Agent.notice_error(e)
      true
    end
  end

  def ddos
    cache_has?(DDOS)
  end

  def find_matching_rule(request)
    @rules.each do |rule|
      return rule if request.path =~ rule.match
    end
    nil
  end

  def apply_rule(request, rule)
    if rule.skip_throttling? request
      logger.debug "[#{self}] #{request.ip}:#{request.host}/#{request.path}: Rate limiting skipped"
      return true
    end

    key = rule.get_key(request)
    record = cache_get(key)
    if record
      logger.debug "[#{self}] #{request.ip}:#{request.host}/#{request.path}: Rate limiting entry: '#{key}' => #{record}"

      current_time = Time.now
      records = record.split(":")
      request_count = records[0].to_i
      reset = Time.at(records[1].to_i)
      rule_limit = records[2].to_i

      if reset > current_time
        # rule hasn't been reset yet
        cache_setex(key, (reset.to_i - current_time.to_i), "#{request_count + 1}:#{reset.to_i}:#{rule_limit}")
        if rule_limit < 0 || request_count < rule_limit
          # within rate limit
          response = get_header(request_count + 1, reset, rule_limit)
        else
          logger.info "[#{self}] #{request.ip}:#{request.host}/#{request.path}: Rate limited; request rejected."
          return false
        end
      else
        response = get_header(1, rule.get_expiration, rule_limit)
        cache_setex(key, rule.get_expiration_sec, "1:#{rule.get_expiration.to_i}:#{rule_limit}")
      end
    else
      rule_limit = rule.limit request
      response = get_header(1, rule.get_expiration, rule_limit)
      cache_setex(key, rule.get_expiration_sec, "1:#{rule.get_expiration.to_i}:#{rule_limit}")
    end
    response
  end

  def get_header(request_count, reset, limit)
    {'x-RateLimit-Limit' => limit.to_s, 'x-RateLimit-Remaining' => (limit - request_count).to_s, 'x-RateLimit-Reset' => reset.strftime("%d%m%y%H%M%S") }
  end

  def xml_error(code, message)
    "<?xml version=\"1.0\"?>\n<error>\n  <code>#{code}</code>\n  <message>#{message}</message>\n</error>"
  end

end
