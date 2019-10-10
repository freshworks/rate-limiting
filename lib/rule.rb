class Rule

  def initialize(options)
    default_options = {
      :match => /.*/,
      :metric => :rph,
      :type => :frequency,
      :limit => 100,
      :per_ip => true,
      :per_url => false,
      :token => false,
      :per_xff_ip => false
    }
    @options = default_options.merge!(options)

  end

  def match
    @options[:match].class == String ? Regexp.new("#{@options[:match]}$") : @options[:match]
  end

  def limit
    (@options[:type] == :frequency ? @options[:frequency_limit] : @options[:limit])
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
    path_url = @options[:include_host] ? "#{request.host}#{request.path}" : request.path
    key = (@options[:per_url] ? path_url : @options[:match].to_s)
    key = "#{key}#{request.ip}" if @options[:per_ip]
    key = "#{key}#{request.env['HTTP_X_FORWARDED_FOR']}" if @options[:per_xff_ip]
    key = "#{key}#{request.params[@options[:token].to_s]}" if @options[:token]
    key
  end
end

