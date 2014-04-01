require "spec_helper"

describe "whilisting of ip" do
	include Rack::Test::Methods
	
	after(:all) do
		$store.flushdb
	end


  it 'should be allowed if not exceed limit' do
    get '/fixed/rpm', {}, {'HTTP_ACCEPT' => "text/html"}
    last_response.body.should show_allowed_response
  end 

  it 'should not be allowed if exceed limit' do
    2.times { get '/fixed/rpm', {}, {'HTTP_ACCEPT' => "text/html"} }
    last_response.body.should show_not_allowed_response
  end 

  it "should allow if exceed limit when whitelisted" do
  	$store.hset("whitelist1","127.0.0.1","test")
  	2.times { get '/fixed/rpm', {}, {'HTTP_ACCEPT' => "text/html"} }
  	last_response.body.should show_allowed_response
  end

  it "should not allow if exceed limit and whitelisted ip is removed" do
  	$store.hdel("whitelist1","127.0.0.1")
  	2.times { get '/fixed/rpm', {}, {'HTTP_ACCEPT' => "text/html"} }
  	last_response.body.should show_not_allowed_response
  end
  
end