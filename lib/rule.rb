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

  def skip_throttling? request
    @options[:skip_limit] ? CustomRateLimit.send(@options[:skip_limit], request) : false
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
    key = key + ':' + request.host.to_s if @options[:per_host]

    request_params = request.params.present? ? request.params : request.env["action_dispatch.request.request_parameters"]
    key = key + ':' + request_params[@options[:token].to_s] if @options[:token]
    key = key + ':' + @options[:param_keys].inject("") {|result, param_key| result += get_param_key_value(request_params, param_key.split(".")) } if @options[:param_keys]

    key
  end

  def get_status_code
    @options[:status_code]
  end

  def get_param_key_value params, key_path
    if params.is_a? Hash
      key = key_path.delete_at(0)

      if key_path.any?
        return get_param_key_value(params[key], key_path) 
      else
        return params[key].to_s
      end
    else
      return ""
    end
  end

end

