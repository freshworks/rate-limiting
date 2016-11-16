require "#{::Rails.root}/lib/custom_rate_limit" if File.exists?(File.join(::Rails.root, 'lib', 'custom_rate_limit.rb'))

class Rule

  def initialize(options)
    default_options = {
      :match => /.*/,
      :metric => :rph,
      :type => :frequency,
      :limit => 100,
      :per_ip => true,
      :per_url => false,
      :per_host => false,
      :token => false
    }
    @options = default_options.merge(options)

  end

  def match
    @options[:match].class == String ? Regexp.new(@options[:match] + "$") : @options[:match]
  end

  def limit request
    rule_limit = nil
    if @options[:custom_limit]
      rule_limit = CustomRateLimit.send(@options[:custom_limit], request)
    else
      rule_limit = (@options[:type] == :frequency ? @options[:frequency_limit] : @options[:limit])
    end

    return rule_limit
  end

  def get_expiration
    (Time.now + ( @options[:type] == :frequency ? get_frequency : get_fixed ))
  end

  def get_frequency
    case @options[:metric]
    when :rpd
      return (86400/@options[:limit] == 0 ? 1 : 86400/@options[:limit])
    when :rph
      return (3600/@options[:limit] == 0 ? 1 : 3600/@options[:limit])
    when :rpm
      return (60/@options[:limit] == 0 ? 1 : 60/@options[:limit])
    end
  end

  def get_fixed
    case @options[:metric]
    when :rpd
      return 86400
    when :rph
      return 3600
    when :rpm
      return 60
    end
  end

  def get_expiration_sec
    (@options[:type] == :frequency) ? get_frequency : get_fixed 
  end

  def get_key(request)
    key = (@options[:per_url] ? request.path : @options[:match].to_s)
    key = key + request.ip.to_s if @options[:per_ip]
    key = key + request.host.to_s if @options[:per_host]
    key = key + request.params[@options[:token].to_s] if @options[:token]
    key
  end
end

