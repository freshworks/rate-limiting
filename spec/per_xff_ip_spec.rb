require "spec_helper"

describe "per_xff_ip rule" do
  include Rack::Test::Methods

    it 'should not allow same url and same xff ips' do
      get '/per_xff/url1', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.55"}
      get '/per_xff/url1', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.55"}
      last_response.body.should show_not_allowed_response
    end
    
    it 'should allow same url but different xff ips' do
      get '/per_xff/url2', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.60"}
      get '/per_xff/url2', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.75"}
      get '/per_xff/url2', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.80"}
      last_response.body.should show_allowed_response
    end

    it 'should not allow different urls and same xff ips' do
      get '/per_xff/url3', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.25"}
      get '/per_xff/url4', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.25"}
      last_response.body.should show_not_allowed_response
    end

    it 'should allow different urls and diff xff ips' do
      get '/per_xff/url5', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.85"}
      get '/per_xff/url6', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.95"}
      last_response.body.should show_allowed_response
    end

    it 'should not allow same url if xff ips is not passed' do
      get '/per_xff/url7', {}, {'HTTP_ACCEPT' => "text/html"}
      get '/per_xff/url7', {}, {'HTTP_ACCEPT' => "text/html"}
      last_response.body.should show_not_allowed_response
    end

    it 'should not allow different url if xff ips is not passed' do
      get '/per_xff/url8', {}, {'HTTP_ACCEPT' => "text/html"}
      get '/per_xff/url9', {}, {'HTTP_ACCEPT' => "text/html"}
      last_response.body.should show_not_allowed_response
    end

    after(:all) do
      $store.flushdb
    end

end

describe "per_xff_ip_per_url rule" do
  include Rack::Test::Methods

    it 'should not allow same url and same xff ips' do
      get '/per_xff_per_url/url1', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.55"}
      get '/per_xff_per_url/url1', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.55"}
      last_response.body.should show_not_allowed_response
    end
    
    it 'should allow same url but different xff ips' do
      get '/per_xff_per_url/url2', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.60"}
      get '/per_xff_per_url/url2', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.75"}
      get '/per_xff_per_url/url2', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.80"}
      last_response.body.should show_allowed_response
    end

    it 'should allow different urls and same xff ips' do
      get '/per_xff_per_url/url3', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.25"}
      get '/per_xff_per_url/url4', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.25"}
      last_response.body.should show_allowed_response
    end

    it 'should allow different urls and diff xff ips' do
      get '/per_xff_per_url/url5', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.85"}
      get '/per_xff_per_url/url6', {}, {'HTTP_ACCEPT' => "text/html", "HTTP_X_FORWARDED_FOR" => "10.23.44.95"}
      last_response.body.should show_allowed_response
    end

    it 'should not allow same url if xff ips is not passed' do
      get '/per_xff_per_url/url7', {}, {'HTTP_ACCEPT' => "text/html"}
      get '/per_xff_per_url/url7', {}, {'HTTP_ACCEPT' => "text/html"}
      last_response.body.should show_not_allowed_response
    end

    it 'should allow different url if xff ips is not passed' do
      get '/per_xff_per_url/url8', {}, {'HTTP_ACCEPT' => "text/html"}
      get '/per_xff_per_url/url9', {}, {'HTTP_ACCEPT' => "text/html"}
      last_response.body.should show_allowed_response
    end

    after(:all) do
      $store.flushdb
    end

end